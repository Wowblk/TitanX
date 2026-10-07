"""Generate the Chinese report from the retained measurements."""
import json
import statistics
from pathlib import Path

root = Path(__file__).resolve().parent
results = json.loads((root / 'results.json').read_text())
names = {'dense': '密集：6 万连续 ID', 'sparse_32': '稀疏：1 万 ID 分散在 10 亿范围', 'clustered': '成簇：100 组，每组 100 个 ID', 'sparse_64': '64 位稀疏：1 万 ID，大于 2^55'}
labels = {'native-sharded': '原生 Bitmap 分片', 'roaring-sharded': 'Roaring 保留分片', 'roaring-single': 'Roaring32 单 Key', 'roaring64-single': 'Roaring64 单 Key'}
lines = ['# KnowFlow Bitmap 对照实验', '',
'结论：稀疏数据下 Roaring 有明显内存收益；密集数据下保留分片未必划算。本机单客户端延迟没有稳定的全面改善，不能据此宣称生产提速。', '',
'## 环境与方法', '',
f"- 系统：{results['platform']}", f"- Redis：{results['redis']}",
'- KnowFlow 基线：103f84d；实验分支：experiment/roaring-bitmap-comparison。',
'- 模块：redis-roaring 360327e0ae79cf87a4fc8e912e28590efd8c2f4c，Release 编译，启用 Redis allocator。',
'- 每个变体独立临时 Redis，Unix socket，关闭持久化；固定数据种子；每项 3 轮。',
'- 主要内存口径：加载数据前后的 used_memory - mem_clients_normal 增量，预热 Lua 并等待后台计数稳定。包含容器、Key 字典等分配，非 RSS。',
'- 模块 MEMORY USAGE 实际报告序列化大小，不能用它直接代表完整内存；原始值和完整 INFO 快照保存在 results.json。',
'- 延迟为 Python 客户端序列化、Lua/Redis 执行及本地往返之和；表中为三轮各自分位数的中位数。',
'- 写延迟包含取消、重复取消、添加、重复添加四种操作；不包含 Kafka、HTTP、Spring 或数据库。', '',
'## 内存与延迟', '',
'| 场景 | 方案 | Key 数 | 内存增量 KiB | 读取 P50/P99 µs | Lua 更新 P50/P99 µs |',
'|---|---|---:|---:|---:|---:|']
for case, rows in results['cases'].items():
    for row in rows:
        def median(field, p): return statistics.median(x[f'p{p}_us'] for x in row[field])
        lines.append(f"| {names[case]} | {labels[row['mode']]} | {row['keys']} | {row['used_memory_delta_bytes']/1024:.2f} | {median('read_rounds',50):.2f} / {median('read_rounds',99):.2f} | {median('toggle_rounds',50):.2f} / {median('toggle_rounds',99):.2f} |")
lines += ['', '## 正确性与边界', '',
'- 15 个场景/变体组合全部验证：每个写入成员、抽样未写入成员、完整基数、重复添加/取消幂等性和更新后基数。',
'- 模块底层单元测试：264/264 通过；脚本 Python 编译检查通过。',
'- 64 位大 ID 保留十进制字符串传给 R64 命令，不经 Lua tonumber 转换，避免 2^53 以上精度损失。',
'- 不执行 R.OPTIMIZE，因此成簇数据反映实时写入状态，而非额外离线压缩后的最佳大小。',
'- 合并成单 Key 的收益包含减少 Key 数量，不等于压缩容器本身的收益；同时会改变集群分布与热点风险。',
'- 只测一个实体/指标，未覆盖真实业务分布、并发竞争、多节点、持久化恢复和迁移。不把此实验作为生产模块稳定性的证明。',
'- Redis 双写与 Kafka 发送的一致性不在本实验范围内；没有修改生产服务或已有数据。', '',
'## 建议', '',
'如果真实点赞 ID 分布接近稀疏场景，值得进一步试点 Roaring；如果是密集小范围，先保留当前方案。当前证据支持“稀疏时省内存”，不支持“必然更快”。',
'实验只实现隔离的存储策略对照原型，没有把 Java CounterService 默认实现切换到第三方模块。生产改造应另行验证依赖兼容、恢复、数据迁移和事件一致性。', '',
'复跑命令与接口契约见 README.md；原始每轮数据见 results.json。', '']
(root/'REPORT.md').write_text('\n'.join(lines))
