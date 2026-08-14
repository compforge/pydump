# Pydump Backlog

## 从 core dump 离线生成 PyHeap v1

为低内存余量和濒临 OOM 的目标进程增加 core capture backend：短暂停止目标进程并生成 ELF core，
随后在进程外恢复 CPython 对象事实，复用现有 Collector 的 `HeapWriter` 生成 PyHeap v1。该后端不经过
Loader 或 Agent，所有随堆规模增长的遍历与写入状态都留在离线进程。

实现参考：

- 复用或移植 [`py-spy` PR #850](https://github.com/benfred/py-spy/pull/850) 的 ELF core、
  CPython 版本布局和 GC generation 遍历能力，不从头实现 Core Reader。
- 从 GC generations、线程 frame locals 和 well-known types 建立根集合，在进程外维护 work queue 和
  visited set。
- 为 CPython 内建容器、普通 Python instance、managed dict 和 slots 提供静态 reference resolver；
  有精确扩展源码和构建信息时，可按 CPython minor、架构和 ELF build-id 生成扩展 resolver。
- 未适配的 C 扩展类型必须标记为 opaque/incomplete，不能把缺失引用边的 retained heap 冒充为精确结果。
  PyHeap v1 无法表达完整度，因此同时产出 capture metadata，记录 opaque types、读取错误和缺失映射。

首个验证闭环限定为 CPython 3.12、Linux x86_64：对同一 fixture 分别执行 live capture 和 core
capture，逐对象比较地址、类型、shallow size、容器内容和引用边；生成的 artifact 必须能被现有
PyHeap `HeapReader` 读取，并测量目标暂停时间、目标峰值 RSS、core 大小和离线解析资源消耗。

## 从 checkpoint 恢复诊断克隆后运行 PyHeap

评估基于 CRIU 或容器运行时 checkpoint/restore 的 clone capture backend：保存运行中 Python 进程或
容器的可恢复状态，将 checkpoint 复制到高内存诊断环境，在隔离沙箱中恢复克隆并运行现有 PyHeap，最后
交付 `.pyheap` 并销毁克隆。PyHeap 的 O(N) 临时状态只进入诊断克隆；由于恢复的是完整 CPython 运行时，
该路线可以继续调用 `gc.get_referents()` 和扩展类型的 `tp_traverse`，对象图完整度预期高于静态 Core
Reader。

该能力属于独立 capture backend，不进入 Loader。恢复环境必须默认阻断网络出口，使用隔离的 PID、
mount 和 network namespace，以及 rootfs/volume 的只读快照或临时副本，避免克隆继续访问生产 DB、MQ、
服务发现、租约和文件。checkpoint 必须记录并校验内核、CPU、容器镜像、共享库和外部资源要求；TCP、
Unix socket、文件锁、特殊设备与 GPU 等不能安全恢复时应在执行 PyHeap 前失败。

首个验证闭环使用 CPython 3.12 的 Linux 容器：原容器在 checkpoint 后继续运行，checkpoint 可在断网的
诊断容器中恢复，恢复进程能够生成可读的 PyHeap v1 artifact，且整个过程不会访问测试用外部服务。
同时对比直接 live capture 的对象数、引用边和 retained heap，并测量 checkpoint 暂停时间、归档大小、
恢复耗时与诊断克隆峰值 RSS。若运行环境无法可靠 checkpoint/restore，再回退到 live-agent 或
core-reader 路线。
