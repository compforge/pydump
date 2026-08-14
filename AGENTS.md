# AGENTS.md

## 项目定位与边界

Pydump 是面向存量 CPython 进程的低目标内存 heap dumper。它通过注入小型 C Agent 流式读取对象事实，
由进程外 Python Collector 维护对象图遍历状态并生成 PyHeap v1 artifact；`analyzer/<language>` 下的
独立实现共享 `pydump.analysis/v1` 契约，在采集结束后离线提供 headless summary 和 retained-heap 分析。

项目内核由 Capture、Contract、Analyzer 三部分组成：Capture 负责取得事实并原子交付 artifact；Contract
是采集、分析实现和消费方的语言中立边界；Analyzer 只离线读取 artifact。项目不负责 Collector 的容器
放置、Kubernetes 编排、UI 或 Doctor 业务集成。Capture 当前支持 Linux glibc、常规 GIL 构建的 CPython
3.10 及以上；注入目标的 glibc baseline 是 2.17。free-threaded CPython、多独立解释器和 musl 不在
支持范围。

## 代码地图与核心模块

```text
<repo_root>/
├── capture/
│   ├── collector/      # Python CLI、attach 编排、O(N) 遍历状态与 artifact writer
│   │   ├── src/pydump/
│   │   ├── tests/
│   │   └── benchmarks/
│   ├── loader/         # 目标环境探测与 Agent Loader；GDB、ptrace 是平行策略
│   │   └── injector/   # ptrace Loader 使用的静态跨进程 helper
│   └── agent/          # 注入目标 CPython 的 C Agent；只保留有界 session 状态
├── analyzer/
│   ├── python/         # Python 参考实现及独立 package
│   └── go/             # 紧凑图结构的 Go 实现及独立 binary
├── contracts/
│   ├── heap-v1.md      # PyHeap v1 artifact 输入兼容边界
│   ├── analysis-v1.md  # pydump.analysis/v1 输出契约
│   └── testdata/       # 所有语言共用的 golden artifact 与 expected JSON
└── docs/kernel.md      # Capture/Contract/Analyzer 内核、资源归属与验证门禁
```

## 关键约定

1. **O(N) 状态只属于 Collector**：全堆 work queue、visited set、类型表和输出文件不得进入 Agent。
   Agent 的任何新增缓存都必须证明其上界不随目标堆对象数增长。
2. **裸地址有效期由 GIL 保护**：Agent 在 Collector 持有对象地址期间持续持有 GIL，并在所有完成、断连和
   超时路径恢复 GC 状态后释放；不能调用可能执行用户代码或修改对象图的 API。
3. **对象图优先于解释元数据**：`tp_traverse` 引用和精确内建容器内容是核心语义。属性、线程 frame、
   shallow size 与预览无法安全取得时允许为空或保守值，不能为补齐信息重新引入目标侧 O(N) 内存。
4. **Contract 是跨实现事实源**：PyHeap v1 是 artifact 输入兼容边界，`pydump.analysis/v1` 是分析输出
   边界；共享 spec 和 golden corpus 高于任一语言实现。内部 Agent 协议可以演进，但握手版本、CPython
   minor、指针宽度、字节序和 nonce 必须严格校验。
5. **CPython minor 是 native ABI 边界**：Agent 必须按目标 Python minor 和架构构建。修改 GC/frame/object
   布局访问时，必须补相应版本的真实 attach 验证，不能仅凭跨版本编译成功认定兼容。
6. **部分 artifact 不得交付**：Collector 写同目录临时文件，只在 Agent 完成、footer 校验和 flush 成功后
   原子改名；任何失败都应保留带 PID、阶段和原始原因的错误上下文。
7. **发布以真实环境矩阵为准**：本地 native smoke 只验证 C/Python 协议和对象遍历。正式发布前必须通过
   Linux glibc 上 CPython 3.10–3.14 × x86_64/AArch64 的 GDB/ptrace Loader、超时恢复和内存预算测试。
8. **分析与采集进程隔离**：Analyzer 只能从已交付 artifact 构建 O(N) 对象图和 inbound index，不得
   通过 Agent 回到目标进程补数据。各语言实现不互相依赖，UI 不进入 Analyzer。

## 开发与验证

Python 或 Go 代码改动后运行 `make fix`、`make lint` 和 `make test`。修改 `capture/agent/`、采集协议或
对象图语义时，额外运行 `make build-agent` 与 `make test-native`；修改
`capture/loader/injector/` 时在 Linux 运行 `make test-ptrace-loader`；修改 artifact writer 时还需运行
`make test-compat`。`make test-compat` 依赖相邻工作区中的 fork-pyheap，仅用于以 upstream reader 验证
公开 artifact 契约。

## References

- `README.md` — 使用者视角的状态、构建、采集和验证入口
- `docs/kernel.md` — Capture/Contract/Analyzer 模型、资源归属、安全边界和发布门禁
- `analyzer/README.md` — 多语言 Analyzer 的实现与运行边界
- `contracts/README.md`、`contracts/analysis-v1.md` — artifact 与分析结果的语言中立契约
- `NOTICE` — PyHeap 兼容实现的来源与许可归属
