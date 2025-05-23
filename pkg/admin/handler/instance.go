/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package handler

// API Definition: https://app.apifox.com/project/3732499
// 资源详情-实例

import (
	"net/http"
	"strconv"
	"strings"
)

import (
	"github.com/gin-gonic/gin"

	"github.com/pkg/errors"
)

import (
	mesh_proto "github.com/apache/dubbo-kubernetes/api/mesh/v1alpha1"
	"github.com/apache/dubbo-kubernetes/pkg/admin/model"
	"github.com/apache/dubbo-kubernetes/pkg/admin/service"
	"github.com/apache/dubbo-kubernetes/pkg/core/consts"
	"github.com/apache/dubbo-kubernetes/pkg/core/resources/apis/mesh"
	core_store "github.com/apache/dubbo-kubernetes/pkg/core/resources/store"
	core_runtime "github.com/apache/dubbo-kubernetes/pkg/core/runtime"
)

func GetInstanceDetail(rt core_runtime.Runtime) gin.HandlerFunc {
	return func(c *gin.Context) {
		req := &model.InstanceDetailReq{}
		if err := c.ShouldBindQuery(req); err != nil {
			c.JSON(http.StatusBadRequest, model.NewErrorResp(err.Error()))
			return
		}

		resp, err := service.GetInstanceDetail(rt, req)
		if err != nil {
			c.JSON(http.StatusInternalServerError, model.NewErrorResp(err.Error()))
			return
		}

		if len(resp) == 0 {
			c.JSON(http.StatusNotFound, model.NewErrorResp("instance not exist"))
			return
		}
		c.JSON(http.StatusOK, model.NewSuccessResp(resp[0]))
	}
}

func SearchInstances(rt core_runtime.Runtime) gin.HandlerFunc {
	return func(c *gin.Context) {
		req := model.NewSearchInstanceReq()
		if err := c.ShouldBindQuery(req); err != nil {
			c.JSON(http.StatusBadRequest, model.NewErrorResp(err.Error()))
			return
		}

		instances, err := service.SearchInstances(rt, req)
		if err != nil {
			c.JSON(http.StatusInternalServerError, model.NewErrorResp(err.Error()))
			return
		}

		c.JSON(http.StatusOK, model.NewSuccessResp(instances))
	}
}

func InstanceConfigTrafficDisableGET(rt core_runtime.Runtime) gin.HandlerFunc {
	return func(c *gin.Context) {
		resp := struct {
			TrafficDisable bool `json:"trafficDisable"`
		}{false}
		applicationName := c.Query("appName")
		if applicationName == "" {
			c.JSON(http.StatusBadRequest, model.NewErrorResp("application name is empty"))
			return
		}
		instanceIP := strings.TrimSpace(c.Query("instanceIP"))
		if instanceIP == "" {
			c.JSON(http.StatusBadRequest, model.NewErrorResp("instanceIP is empty"))
			return
		}

		res, err := service.GetConditionRule(rt, applicationName)
		if err != nil {
			if core_store.IsResourceNotFound(err) {
				c.JSON(http.StatusOK, model.NewSuccessResp(resp))
				return
			}
			c.JSON(http.StatusInternalServerError, model.NewErrorResp(err.Error()))
			return
		}

		if res.Spec.GetVersion() != consts.ConfiguratorVersionV3 {
			c.JSON(http.StatusServiceUnavailable, model.NewErrorResp("this config only serve condition-route.configVersion == v3, got v3.1 config "))
			return
		}

		cr := res.Spec.ToConditionRouteV3()
		cr.RangeConditions(func(condition string) (isStop bool) {
			_, resp.TrafficDisable = isTrafficDisabledV3(condition, instanceIP)
			return resp.TrafficDisable
		})

		c.JSON(http.StatusOK, model.NewSuccessResp(resp))
	}
}

func isTrafficDisabledV3X1(r *mesh_proto.ConditionRule, targetIP string) bool {
	if len(r.To) != 0 {
		return false
	}
	// rule must match `host=x1{,x2,x3}`
	if r.From.Match != "" && !strings.Contains(r.From.Match, "&") && strings.Index(r.From.Match, "!=") == -1 {
		idx := strings.Index(r.From.Match, "=")
		if idx == -1 {
			return false
		}
		then := r.From.Match[idx+1:]
		Ips := strings.Split(then, ",")
		for _, ip := range Ips {
			if strings.TrimSpace(ip) == targetIP {
				return true
			}
		}
	}
	return false
}

/*
*
isTrafficDisabledV3 judge if a condition is disabled or not.
A condition include fromCondition and toCondition which is seperated by `=>`.
The first return parameter `exist` indicates if a condition of specific targetIP exists.
The second return parameter `disabled` indicates if the traffic of targetIP is disabled.
*/
func isTrafficDisabledV3(condition string, targetIP string) (exist bool, disabled bool) {
	if len(condition) == 0 {
		return false, false
	}
	condition = strings.ReplaceAll(condition, " ", "")
	// only accept string start with `=>`
	if !strings.HasPrefix(condition, "=>") {
		return false, false
	}
	toCondition := strings.TrimPrefix(condition, "=>")
	// TODO more specific judge
	if !strings.Contains(toCondition, targetIP) {
		return false, false
	}
	targetExpression := "host!=" + targetIP
	if targetExpression != toCondition {
		return true, false
	}
	return true, true
}

func InstanceConfigTrafficDisablePUT(rt core_runtime.Runtime) gin.HandlerFunc {
	return func(c *gin.Context) {
		appName := strings.TrimSpace(c.Query("appName"))
		if appName == "" {
			c.JSON(http.StatusBadRequest, model.NewErrorResp("application name is empty"))
			return
		}
		instanceIP := strings.TrimSpace(c.Query("instanceIP"))
		if instanceIP == "" {
			c.JSON(http.StatusBadRequest, model.NewErrorResp("instanceIP is empty"))
			return
		}
		newDisabled, err := strconv.ParseBool(c.Query(`trafficDisable`))
		if err != nil {
			c.JSON(http.StatusBadRequest, model.NewErrorResp(errors.Wrap(err, "parse trafficDisable fail").Error()))
			return
		}

		existRule := true
		rawRes, err := service.GetConditionRule(rt, appName)
		var res *mesh_proto.ConditionRouteV3
		if err != nil {
			if !core_store.IsResourceNotFound(err) {
				c.JSON(http.StatusInternalServerError, model.NewErrorResp(err.Error()))
				return
			} else if !newDisabled { // not found && cancel traffic-disable
				c.JSON(http.StatusOK, model.NewSuccessResp(nil))
				return
			}
			existRule = false
			res = generateDefaultConditionV3(true, true, true, appName, consts.ScopeApplication)
			rawRes = &mesh.ConditionRouteResource{Spec: res.ToConditionRoute()}
		} else if res = rawRes.Spec.ToConditionRouteV3(); res == nil {
			c.JSON(http.StatusServiceUnavailable, model.NewErrorResp("this config only serve condition-route.configVersion == v3.1, got v3.0 config "))
			return
		}

		// enable traffic
		if !newDisabled {
			for i, condition := range res.Conditions {
				existCondition, oldDisabled := isTrafficDisabledV3(condition, instanceIP)
				if existCondition {
					if oldDisabled != newDisabled {
						res.Conditions = append(res.Conditions[:i], res.Conditions[i+1:]...)
						rawRes.Spec = res.ToConditionRoute()
						if err = updateORCreateConditionRule(rt, existRule, appName, rawRes); err != nil {
							c.JSON(http.StatusInternalServerError, model.NewErrorResp(err.Error()))
						}
						c.JSON(http.StatusOK, model.NewSuccessResp(nil))
						return
					}
				}
			}
		} else { // disable traffic
			// check if condition exists
			for _, condition := range res.Conditions {
				existCondition, oldDisabled := isTrafficDisabledV3(condition, instanceIP)
				if existCondition && oldDisabled {
					c.JSON(http.StatusBadRequest, model.NewErrorResp("The instance has been disabled!"))
					return
				}
			}
			res.Conditions = append(res.Conditions, disableExpression(instanceIP))
			if err = updateORCreateConditionRule(rt, existRule, appName, rawRes); err != nil {
				c.JSON(http.StatusInternalServerError, model.NewErrorResp(err.Error()))
			}
			c.JSON(http.StatusOK, model.NewSuccessResp(nil))
		}
	}
}

func disableExpression(instanceIP string) string {
	return "=>host!=" + instanceIP
}
func updateORCreateConditionRule(rt core_runtime.Runtime, existRule bool, appName string, rawRes *mesh.ConditionRouteResource) error {
	if !existRule {
		return service.CreateConditionRule(rt, appName, rawRes)
	} else {
		return service.UpdateConditionRule(rt, appName, rawRes)
	}
}

func newDisableConditionV3x1(ip string) *mesh_proto.ConditionRule {
	return &mesh_proto.ConditionRule{
		From: &mesh_proto.ConditionRuleFrom{Match: "host=" + ip},
		To:   nil,
	}
}

func newDisableConditionV3(ip string) string {
	return "=>host!=" + ip
}

func generateDefaultConditionV3x1(Enabled, Force, Runtime bool, Key, Scope string) *mesh_proto.ConditionRouteV3X1 {
	return &mesh_proto.ConditionRouteV3X1{
		ConfigVersion: consts.ConfiguratorVersionV3x1,
		Enabled:       Enabled,
		Force:         Force,
		Runtime:       Runtime,
		Key:           Key,
		Scope:         Scope,
		Conditions:    make([]*mesh_proto.ConditionRule, 0),
	}
}

func generateDefaultConditionV3(Enabled, Force, Runtime bool, Key, Scope string) *mesh_proto.ConditionRouteV3 {
	return &mesh_proto.ConditionRouteV3{
		ConfigVersion: consts.ConfiguratorVersionV3,
		Priority:      0,
		Enabled:       true,
		Force:         Force,
		Runtime:       Runtime,
		Key:           Key,
		Scope:         Scope,
		Conditions:    make([]string, 0),
	}
}

func InstanceConfigOperatorLogGET(rt core_runtime.Runtime) gin.HandlerFunc {
	return func(c *gin.Context) {
		resp := struct {
			OperatorLog bool `json:"operatorLog"`
		}{false}
		applicationName := c.Query(`appName`)
		if applicationName == "" {
			c.JSON(http.StatusBadRequest, model.NewErrorResp("application name is empty"))
			return
		}
		instanceIP := c.Query(`instanceIP`)
		if instanceIP == "" {
			c.JSON(http.StatusBadRequest, model.NewErrorResp("instanceIP is empty"))
			return
		}

		res, err := service.GetConfigurator(rt, applicationName)
		if err != nil {
			if core_store.IsResourceNotFound(err) {
				c.JSON(http.StatusOK, model.NewSuccessResp(resp))
				return
			}
			c.JSON(http.StatusNotFound, model.NewErrorResp(err.Error()))
			return
		}

		if res.Spec.Enabled {
			res.Spec.RangeConfig(func(conf *mesh_proto.OverrideConfig) (isStop bool) {
				resp.OperatorLog = isInstanceOperatorLogOpen(conf, instanceIP)
				return resp.OperatorLog
			})
		}

		c.JSON(http.StatusOK, model.NewSuccessResp(resp))
	}
}

func isInstanceOperatorLogOpen(conf *mesh_proto.OverrideConfig, IP string) bool {
	if conf != nil &&
		conf.Match != nil &&
		conf.Match.Address != nil &&
		conf.Match.Address.Wildcard == IP+`:*` &&
		conf.Side == consts.SideProvider &&
		conf.Parameters != nil &&
		conf.Parameters[`accesslog`] == `true` {
		return true
	}
	return false
}

func InstanceConfigOperatorLogPUT(rt core_runtime.Runtime) gin.HandlerFunc {
	return func(c *gin.Context) {
		applicationName := c.Query(`appName`)
		if applicationName == "" {
			c.JSON(http.StatusBadRequest, model.NewErrorResp("application name is empty"))
			return
		}
		instanceIP := c.Query(`instanceIP`)
		if instanceIP == "" {
			c.JSON(http.StatusBadRequest, model.NewErrorResp("instanceIP is empty"))
			return
		}
		adminOperatorLog, err := strconv.ParseBool(c.Query(`operatorLog`))
		if err != nil {
			c.JSON(http.StatusBadRequest, model.NewErrorResp(err.Error()))
			return
		}

		res, err := service.GetConfigurator(rt, applicationName)
		notExist := false
		if err != nil {
			if !core_store.IsResourceNotFound(err) {
				c.JSON(http.StatusNotFound, model.NewErrorResp(err.Error()))
				return
			}
			res = generateDefaultConfigurator(applicationName, consts.ScopeApplication, consts.ConfiguratorVersionV3, true)
			notExist = true
		}

		if !adminOperatorLog {
			res.Spec.RangeConfigsToRemove(func(conf *mesh_proto.OverrideConfig) (IsRemove bool) {
				return isInstanceOperatorLogOpen(conf, instanceIP)
			})
		} else {
			var isExist bool
			res.Spec.RangeConfig(func(conf *mesh_proto.OverrideConfig) (isStop bool) {
				isExist = isInstanceOperatorLogOpen(conf, instanceIP)
				return isExist
			})
			if !isExist {
				res.Spec.Configs = append(res.Spec.Configs, &mesh_proto.OverrideConfig{
					Side:          consts.SideProvider,
					Match:         &mesh_proto.ConditionMatch{Address: &mesh_proto.AddressMatch{Wildcard: instanceIP + `:*`}},
					Parameters:    map[string]string{`accesslog`: `true`},
					XGenerateByCp: true,
				})
			}
		}

		if notExist {
			err = service.CreateConfigurator(rt, applicationName, res)
			if err != nil {
				c.JSON(http.StatusInternalServerError, model.NewErrorResp(err.Error()))
				return
			}
		} else {
			err = service.UpdateConfigurator(rt, applicationName, res)
			if err != nil {
				c.JSON(http.StatusInternalServerError, model.NewErrorResp(err.Error()))
				return
			}
		}

		c.JSON(http.StatusOK, model.NewSuccessResp(nil))
	}
}
