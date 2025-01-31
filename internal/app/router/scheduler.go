package router

import (
	"context"
	"iptv/internal/app/iptv"
	"time"

	"go.uber.org/zap"
)

const waitSeconds = 30

// Schedule 定时调度更新缓存数据
func Schedule(ctx context.Context, iptvClient iptv.Client, duration time.Duration) {
	// 创建定时任务
	ticker := time.NewTicker(duration)
	go func() {
		for {
			select {
			case <-ctx.Done():
				logger.Info("The scheduling task has been stopped.")
				return
			case <-ticker.C:
				logger.Info("Start executing the scheduling task.")

				// 更新频道列表数据
				if err := updateChannelsWithRetry(ctx, iptvClient, 3); err != nil {
					logger.Error("Failed to update channel list.", zap.Error(err))
				}

				logger.Info("The scheduling task has been completed.")
			}
		}
	}()
}
