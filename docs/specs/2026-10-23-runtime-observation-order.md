# 二进制验收的异步观察检查点

[Windows CI 39922895240](https://github.com/279814/relay-gate/actions/runs/39922895240/job/120312144786) 中，三次请求的 Execution 均已持久化，但学习计数未达到预期。旧验收连续发出 complete/partial/gzip，再要求两个成功都已学习；客户端收到 EOF 并不等待观察工作线程完成。

生产 Store 会将比已提交观察顺序更早的结果标记为 superseded；TrafficObserver 只有 current 的正常成功可以学习。因此，独立工作线程的完成顺序不是该验收可以依赖的前提。原 CI 未记录具体计数和应用结果，不能据此断言某个生产写入失败。

验收改为每个响应后等待对应 Execution 和严格的学习计数，再进入下一种 wire 场景。保留原字节、完整/partial 事实、候选 revision=1、隐私、样本开关、轮换屏障和冷启动的全部断言，不增加睡眠或放宽超时/计数。失败时只输出该合成夹具的观察状态与计数，不输出请求正文或凭据。实际并发、迟到及 superseded 行为仍由生产 Go 回归覆盖。
