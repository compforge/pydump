# Pydump 设计

## 理念与边界

Pydump 面向无法预先植入 profiler、也不能重启的 CPython 进程，采集当前存活对象、引用关系和线程根，
生成可离线分析的 heap artifact。它解决的核心问题不是降低 dump 本身的总资源成本，而是改变资源归属：
目标进程只承担有界的采集 agent 开销，随堆规模增长的队列、去重索引和文件缓存由 Collector 承担。

系统只有两个运行时角色：

- **Collector** 负责 attach 编排、对象图遍历状态、artifact 写入和失败收口。它拥有全部随堆规模增长的
  内存和文件 page cache；具体如何部署 Collector 由调用方决定，不进入 Pydump 的采集模型。
- **Agent** 是注入目标进程的 C 共享库。它在持有 GIL 时读取 Collector 指定的对象，通过有界 socket
  协议返回事实，不保存全堆队列、visited set 或 dump 文件。

Pydump 保持 fork-pyheap 的操作面：`pyheap_dump` 命令、参数、默认值、主要退出行为和 `.pyheap` v1
artifact 均兼容。现有 PyHeap UI、Doctor analyzer 和 `pyheap.analysis/v1` 链路无需理解 Pydump 内部协议。
兼容指读取结果和对象图语义兼容，不要求两个 dumper 生成字节完全相同的文件。

支持范围是 Linux glibc、常规 GIL 构建的 CPython 3.10 及以上，首个验证矩阵覆盖 3.10–3.14、
x86_64 和 AArch64。新增 CPython minor 必须先补齐 adapter 和真实 attach 测试。free-threaded CPython、
多个独立解释器以及 musl 不在当前支持范围；兼容性探测无法确认时必须在遍历前失败。

## 采集流程

```text
解析 PID、namespace 和目标 CPython 版本
  ↓
Collector 创建临时 artifact 和目标可见的 Unix socket
  ↓
GDB 在安全的 Python 执行点 dlopen 对应版本的 C Agent
  ↓
Agent 启动线程，GDB detach，Agent 获取 GIL 并暂停自动 GC
  ↓
Agent 流式发送 well-known type、GC roots 和线程根
  ↓
Collector 维护待访问地址和去重集合，分批请求对象
  ↓
Agent 流式返回对象大小、容器内容、referents 和可选元数据
  ↓
Collector 写完 .pyheap v1，回填对象数并校验 footer
  ↓
Agent 恢复 GC、释放 GIL；Collector 原子交付 artifact 并清理 session
```

GDB 只承担跨 namespace attach、加载共享库和调用启动入口，不执行完整 dump，也不通过
`PyRun_String` 向目标解释器注入 Python 脚本。Agent 在线程中等待 GIL，因此 snapshot 的起点是 Agent
成功获取 GIL 并完成握手的时刻，而不是 GDB 最初 attach 的时刻。

Agent 获取 GIL 后显式暂停自动 GC，并在整个地址有效期内持有 GIL。Collector 保存的是裸对象地址，
不是目标进程中的强引用；因此 Agent 不得在图遍历期间执行可能修改对象图的用户代码。正常完成、协议失败、
Collector 断开或 I/O 超时都必须恢复原 GC 状态并释放 GIL。socket 采用有界缓冲和带 deadline 的
非阻塞 I/O，避免 Collector 卡死后永久暂停业务进程。

## 关键设计

### O(N) 状态属于 Collector

Collector 在对象首次入队时去重，避免高入度图把工作队列放大到 O(E)。它拥有以下随堆规模增长的状态：

- 已调度对象地址集合和待访问批次；
- 当前对象返回的 referents、容器内容和属性；
- 类型地址到名称的映射；
- `.pyheap` writer、对象计数回填和文件 page cache。

Agent 只保留一个 session、固定大小的地址批次和 I/O buffer。根枚举不能调用 `gc.get_objects()`，因为
该 API 会先在目标解释器创建全量对象列表。CPython 3.12 及以上使用
`PyUnstable_GC_VisitObjects`；3.10–3.11 通过按 minor 构建的 GC adapter 直接遍历 generation 链。
线程栈和 locals 同样由版本 adapter 流式读取，不能先在目标侧构造全量 frame/list；对应能力未验证时
保持为空，而不是调用会物化 frame 或 locals 的 Python API。

目标侧内存上界只涵盖 Pydump 自己可控的开销。第三方扩展若违反 `tp_traverse` 契约，或 native 线程在
没有 GIL 的情况下修改 Python 对象，均不属于可保证的安全模型。

### Agent 生命周期可重复使用

Agent 使用目标进程内稳定、按版本和架构区分的路径。首次 `dlopen` 后，共享库作为进程级诊断模块保持
映射；后续 dump 复用同一模块，而不是每次加载一个新 inode。启动入口通过原子 session 状态拒绝并发
采集，异常 session 在连接 deadline 到期后回到 idle。

这种生命周期避免重复诊断不断累积共享库映射。每次 session 的线程、socket 和临时状态必须释放；
Agent 文件本身可以保留到目标进程退出或由外部清理，但不得在仍需复用时替换为内容不同的二进制。

### `.pyheap` v1 是外部兼容边界

Collector 按 PyHeap v1 顺序写入 header、线程信息、属性压缩表、common type 信息、对象区、类型表和
footer。对象区允许流式写入并在 Collector 文件中回填数量。well-known type 地址由 Agent 提供；
frequent attribute 与 common type 表允许为空，不能为了重现 PyHeap 的压缩策略而在目标侧预扫描全堆。

对象图必须保留 `tp_traverse` 关系以及精确 `dict/list/set/tuple` 的容器内容。类型、shallow size、线程
locals、属性和字符串预览属于解释信息；某项无法安全取得时记录 warning 并使用格式允许的空值，不能
牺牲引用图正确性或重新引入目标侧 O(N) 状态。

### Full 是安全的静态元数据，不执行用户代码

`--no-attribute` 与 `--str-repr-len` 参数保持不变，但 Pydump 不复刻 PyHeap 中会调用用户代码的
`dir(obj)`、`str(obj)` 或自定义 `__sizeof__`。这些调用既可能先生成超大临时对象，也可能修改引用图，
从而让 Collector 保存的裸地址失效。

shallow size 对 CPython 核心内建类型和未覆写 `type.__sizeof__` 的类型对象使用 minor 对应的静态布局或
CPython 内建实现精确计算；扩展类型和应用类型若可能覆写语义，则只记录包含 pre-header 的保守分配下界。
这允许分析结果接近 `sys.getsizeof()`，同时不执行应用或扩展对象的 `__sizeof__`。

Full 模式只采集能通过 CPython 布局和静态字典安全读取的属性，并为精确内建类型生成长度受限的字符串
预览；普通用户对象使用不调用 `__str__`/`__repr__` 的类型与地址摘要。当前实现统一生成类型与地址摘要，
并将属性表保持为空；后续增加静态元数据时仍遵守同一安全边界。无法静态读取的属性可以省略。
因此 Lite 和 Full 都不在目标进程保留随对象总数增长的结构；Full 只是返回更多有界的逐对象元数据，
不承诺与 PyHeap 的自定义方法输出逐字段一致。

### 失败不交付半份快照

Collector 始终写同目录临时文件，只有收到 Agent 完成帧、写入合法 footer 并重新读取校验后才原子改名。
attach、版本校验、协议、磁盘或 Agent 任一环节失败都删除本地临时 artifact，并输出包含 PID、采集阶段和
原始原因的错误。Agent 恢复目标进程优先于报告错误；Collector 被强制终止时由 Agent 的 socket EOF 或
deadline 完成兜底恢复。

## 公开接口

Pydump 发布 `pyheap_dump` 可执行文件，并支持 `python -m pydump`。兼容参数包括：

- `--pid/-p` 与 `--docker-container`；
- `--file/-f`；
- `--str-repr-len`，其中 `-1` 禁用字符串预览；
- `--no-attribute`；
- `--ignore-compatibility-checks`；
- `--force-shadow`。

进度继续表达已完成对象数和待访问对象数。输出文件重名时沿用递增后缀行为。内部 Agent 协议不是公开
artifact 契约，仅要求 Collector 与 Agent 握手时校验协议版本、CPython minor、指针宽度、字节序和
session nonce；任一不一致立即终止，不能尝试降级解析。

## 验证标准

- **CLI 契约**：覆盖参数、默认值、互斥 target、退出码、重名输出、Ctrl+C 和错误上下文。
- **Artifact 契约**：用固定版本的 upstream PyHeap `HeapReader` 读取 Pydump 产物，核对对象、类型、
  shallow size、引用、容器内容、线程根、属性和字符串预览。
- **图语义**：覆盖循环引用、高 fanout dict、百万对象、线程 locals、常见容器、属性不可读和自定义
  `__str__`；后两者不得导致用户代码执行。
- **协议恢复**：覆盖短读写、断连、超时、错误版本、Collector 崩溃和磁盘写失败，确认目标重新运行且
  不交付部分 artifact。
- **内存归属**：在 10 万和 100 万对象 fixture 上分别测量目标进程与 Collector。目标侧增量必须受固定
  budget 约束且不随对象数线性增长，Collector 增量允许随对象数增长；目标进程不得打开 dump 文件。
- **真实 attach 矩阵**：CPython 3.10–3.14 × x86_64/AArch64 使用 native Linux 环境执行 GDB attach；
  QEMU 只用于交叉构建和基础 smoke test，不能替代发布门禁。
- **兼容消费方**：同一 artifact 通过现有 PyHeap UI 和 Doctor analyzer，Doctor 仅替换 dumper 资产即可
  完成采集与报告。

Apache-2.0 是项目及派生代码的许可边界。复用 PyHeap 的 CLI、namespace、writer 或 GDB 编排实现时，
必须保留对应版权头和 NOTICE；Memray、Guppy 等项目只作为实现思路参考，实际代码复用遵循各自许可。
