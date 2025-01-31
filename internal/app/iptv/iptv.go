package iptv

import (
	"context"
)

type Client interface {
	// GetAllChannelList 获取频道列表
	GetAllChannelList(ctx context.Context) ([]Channel, error)
}
