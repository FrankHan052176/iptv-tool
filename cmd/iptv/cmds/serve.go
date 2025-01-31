package cmds

import (
	"encoding/json"
	"errors"
	"fmt"
	"iptv/internal/app/router"
	"os"
	"strconv"
	"time"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var httpConfig HttpConfig

type HttpConfig struct {
	Port     int           `json:"port"`
	UdpxyURL string        `json:"udpxyURL"`
	Interval time.Duration `json:"interval"`
	LiveFile string        `json:"liveFile"`
}

func NewServeCLI() *cobra.Command {
	serveCmd := &cobra.Command{
		Use:   "serve",
		Short: "启动HTTP服务，提供直播源等查询接口。",
		RunE: func(cmd *cobra.Command, args []string) error {
			// 读取直播配置
			if httpConfig.LiveFile != "" {
				content, err := os.ReadFile(httpConfig.LiveFile)
				if err != nil {
					return err
				}

				var lives router.Lives
				err = json.Unmarshal(content, &lives)
				if err != nil {
					return err
				}

				// 加载配置内容
				router.LoadLivesConfig(&lives)
			}

			// 检查自动更新间隔不能太短
			if httpConfig.Interval < 15*time.Minute {
				return errors.New("interval cannot be less than 15 minutes")
			}

			// 创建并启动HTTP服务
			r, err := router.NewEngine(cmd.Context(), conf, httpConfig.Interval, httpConfig.UdpxyURL)
			if err != nil {
				return err
			}
			// L()：获取全局logger
			logger := zap.L()
			logger.Info("Start the http service.", zap.String("port", strconv.Itoa(httpConfig.Port)))
			if err = r.Run(fmt.Sprintf(":%d", httpConfig.Port)); err != nil {
				return err
			}

			return nil
		},
	}

	serveCmd.Flags().IntVarP(&httpConfig.Port, "port", "p", 8080, "HTTP服务的监听端口。")
	serveCmd.Flags().StringVarP(&httpConfig.UdpxyURL, "udpxy", "u", "", "如果有安装udpxy进行组播转单播，请配置HTTP地址，e.g `http://192.168.1.1:4022`。")
	serveCmd.Flags().DurationVarP(&httpConfig.Interval, "interval", "i", 24*time.Hour, "自动刷新频道列表和节目单的间隔时间，e.g `24h或15m`。")
	serveCmd.Flags().StringVarP(&httpConfig.LiveFile, "livefile", "l", "", "加载FongMi的直播配置json文件，并提供查询接口。")

	return serveCmd
}
