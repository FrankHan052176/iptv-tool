package router

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

type Lives struct {
	Lives []Live `json:"lives"`
}

// Live 直播配置
type Live struct {
	Name    string `json:"name"`              // 配置名称
	Boot    bool   `json:"boot"`              // 是否自启动
	Url     string `json:"url"`               // 直播源地址
	Logo    string `json:"logo,omitempty"`    // 台标地址
	Pass    bool   `json:"pass,omitempty"`    // 是否免密码
	Ua      string `json:"ua,omitempty"`      // 用户代理
	Origin  string `json:"origin,omitempty"`  // 来源
	Referer string `json:"referer,omitempty"` // 参照地址
}

var lives *Lives

// LoadLivesConfig 加载直播配置
func LoadLivesConfig(livesCfg *Lives) {
	lives = livesCfg
}

// GetLivesConfig 查询直播配置
func GetLivesConfig(c *gin.Context) {
	if lives == nil {
		c.Status(http.StatusNotFound)
		return
	}

	// 返回响应
	c.JSON(http.StatusOK, lives)
}
