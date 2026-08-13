# AGENTS.md

## 项目定位与边界

Pydump 是面向存量 CPython 进程的低目标内存 heap dumper。它通过注入小型 C Agent 流式读取对象事实，
由进程外 Python Collector 维护对象图遍历状态并生成 PyHeap v1 artifact；独立的 `pydump_analysis` 包在
采集结束后离线读取 artifact，提供 headless summary 和 retained-heap 分析。

项目负责 CPython attach、采集协议、对象图语义和 artifact 兼容，不负责 Collector 的容器放置、
Kubernetes 编排或 Doctor 业务集成。当前支持边界是 Linux glibc、常规 GIL 构建的 CPython 3.10 及以上；
free-threaded CPython、多独立解释器和 musl 不在支持范围。

## 代码地图与核心模块

```text
<repo_root>/
├── src/pydump/
│   ├── cli.py          # pyheap_dump 兼容入口与一次采集的生命周期编排
│   ├── target.py       # 目标 PID、namespace 和 CPython minor 识别
│   ├── injector.py     # Agent 安装与 GDB dlopen/start 编排
│   ├── collector.py    # 对象图 work queue、去重、协议消费与失败收口
│   ├── protocol.py     # Collector 与 Agent 的有界二进制协议
│   ├── heap_writer.py  # PyHeap v1 artifact 的唯一 writer
│   └── model.py        # Collector 内部对象、容器和线程事实模型
├── src/pydump_analysis/
│   ├── reader.py       # mmap 读取 PyHeap v1，不依赖采集实现
│   ├── retained.py     # inbound-reference 索引、retained heap 与缓存
│   ├── report.py       # pyheap.analysis/v1 稳定 JSON 契约
│   └── cli.py          # pydump_analyzer headless 入口
├── native/
│   ├── agent.c         # 注入目标进程的 C Agent；只保留有界 session 状态
│   ├── object_facts.c  # 按 CPython minor 安全读取类型名与 shallow size
│   └── protocol.h      # C 侧协议常量，与 Python protocol.py 对应
├── tests/              # CLI、协议、artifact、Collector 与 native smoke 契约测试
└── docs/design.md      # 内存归属、安全模型、采集流程与发布验证标准
```

## 关键约定

1. **O(N) 状态只属于 Collector**：全堆 work queue、visited set、类型表和输出文件不得进入 Agent。
   Agent 的任何新增缓存都必须证明其上界不随目标堆对象数增长。
2. **裸地址有效期由 GIL 保护**：Agent 在 Collector 持有对象地址期间持续持有 GIL，并在所有完成、断连和
   超时路径恢复 GC 状态后释放；不能调用可能执行用户代码或修改对象图的 API。
3. **对象图优先于解释元数据**：`tp_traverse` 引用和精确内建容器内容是核心语义。属性、线程 frame、
   shallow size 与预览无法安全取得时允许为空或保守值，不能为补齐信息重新引入目标侧 O(N) 内存。
4. **PyHeap v1 是外部兼容边界**：artifact 的顺序和读取语义由 upstream `HeapReader` 契约测试保证；
   内部 Agent 协议可以演进，但握手版本、CPython minor、指针宽度、字节序和 nonce 必须严格校验。
5. **CPython minor 是 native ABI 边界**：Agent 必须按目标 Python minor 和架构构建。修改 GC/frame/object
   布局访问时，必须补相应版本的真实 attach 验证，不能仅凭跨版本编译成功认定兼容。
6. **部分 artifact 不得交付**：Collector 写同目录临时文件，只在 Agent 完成、footer 校验和 flush 成功后
   原子改名；任何失败都应保留带 PID、阶段和原始原因的错误上下文。
7. **发布以真实环境矩阵为准**：本地 native smoke 只验证 C/Python 协议和对象遍历。正式发布前必须通过
   Linux glibc 上 CPython 3.10–3.14 × x86_64/AArch64 的 GDB attach、超时恢复和内存预算测试。
8. **分析与采集进程隔离**：`pydump_analysis` 只能从已交付 artifact 构建 O(N) 对象图和 inbound index，
   不得通过 Agent 回到目标进程补数据。`pyheap.analysis/v1` 是分析消费方契约，UI 不进入该包。

## 开发与验证

Python 代码改动后运行 `make fix`、`make lint` 和 `make test`。修改 `native/`、协议或对象图语义时，
额外运行 `make build-agent` 与 `make test-native`；修改 artifact writer 时还需运行 `make test-compat`。
`make test-compat` 依赖相邻工作区中的 fork-pyheap，仅用于以 upstream reader 验证公开 artifact 契约。

## References

- `README.md` — 使用者视角的状态、构建、采集和验证入口
- `docs/design.md` — Collector/Agent 模型、内存归属、安全边界和发布门禁
- `NOTICE` — PyHeap 兼容实现的来源与许可归属
