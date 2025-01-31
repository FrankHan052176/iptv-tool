package hwctc

import (
	"errors"
)

type Config struct {
	InterfaceName string `json:"interfaceName" yaml:"interfaceName"` // 网络接口的名称。若配置则生成Authenticator时，优先使用该接口对应的IPv4地址，而不使用`ip`字段的值。
	// 以下信息均可通过抓包获取
	IP string `json:"ip" yaml:"ip"` // 生成Authenticator所需的IP地址。可随便一个地址，或者通过配置`interfaceName`动态获取
	// 以下信息均可通过抓包请求ValidAuthenticationHWCTC.jsp的参数拿到
	UserID           string `json:"userID" yaml:"userID"`
	Lang             string `json:"lang,omitempty" yaml:"lang,omitempty"`           // 如果没有可以不填
	NetUserID        string `json:"netUserID,omitempty" yaml:"netUserID,omitempty"` // 如果没有可以不填
	STBType          string `json:"stbType" yaml:"stbType"`
	STBVersion       string `json:"stbVersion" yaml:"stbVersion"`
	Conntype         string `json:"conntype" yaml:"conntype"`
	STBID            string `json:"stbID" yaml:"stbID"` // 机顶盒背面也可查
	TemplateName     string `json:"templateName" yaml:"templateName"`
	AreaId           string `json:"areaId" yaml:"areaId"`
	UserGroupId      string `json:"userGroupId,omitempty" yaml:"userGroupId,omitempty"`
	ProductPackageId string `json:"productPackageId,omitempty" yaml:"productPackageId,omitempty"`
	MAC              string `json:"mac" yaml:"mac"` // 机顶盒背面也可查
	UserField        string `json:"userField,omitempty" yaml:"userField,omitempty"`
	SoftwareVersion  string `json:"softwareVersion" yaml:"softwareVersion"`
	IsSmartStb       string `json:"isSmartStb,omitempty" yaml:"isSmartStb,omitempty"`
	Vip              string `json:"vip,omitempty" yaml:"vip,omitempty"`
}

func (c *Config) Validate() error {
	// 校验config配置
	if (c.IP == "" && c.InterfaceName == "") ||
		c.UserID == "" ||
		c.STBType == "" ||
		c.STBVersion == "" ||
		c.STBID == "" ||
		c.MAC == "" {
		return errors.New("invalid HWCTC IPTV client config")
	}

	return nil
}
