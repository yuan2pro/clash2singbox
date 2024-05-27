package convert

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"reflect"
	"strings"
	"github.com/samber/lo"
	"github.com/xmdhs/clash2singbox/model/clash"
	"github.com/xmdhs/clash2singbox/model/singbox"
)

func filter(isinclude bool, reg string, sl []string) ([]string, error) {
	r, err := regexp.Compile(reg)
	if err != nil {
		return sl, fmt.Errorf("filter: %w", err)
	}
	return getForList(sl, func(v string) (string, bool) {
		has := r.MatchString(v)
		if has && isinclude {
			return v, true
		}
		if !isinclude && !has {
			return v, true
		}
		return "", false
	}), nil
}

func getForList[K, V any](l []K, check func(K) (V, bool)) []V {
	sl := make([]V, 0, len(l))
	for _, v := range l {
		s, ok := check(v)
		if !ok {
			continue
		}
		sl = append(sl, s)
	}
	return sl
}

// func getServers(s []singbox.SingBoxOut) []string {
// 	m := map[string]struct{}{}
// 	return getForList(s, func(v singbox.SingBoxOut) (string, bool) {
// 		server := v.Server
// 		_, has := m[server]
// 		if server == "" || has {
// 			return "", false
// 		}
// 		m[server] = struct{}{}
// 		return server, true
// 	})
// }

func getTags(s []singbox.SingBoxOut) []string {
	return getForList(s, func(v singbox.SingBoxOut) (string, bool) {
		tag := v.Tag
		if tag == "" || v.Ignored {
			return "", false
		}
		return tag, true
	})
}

func Patch(b []byte, s []singbox.SingBoxOut, include, exclude string, extOut []interface{}, extags ...string) ([]byte, error) {
	nodes, err := getExtTag(string(b))
	if err != nil {
		return nil, fmt.Errorf("convert2sing: %w", err)
	}
	outs := make([]any, 0, len(nodes)+len(extOut))
	extTag := make([]string, 0, len(nodes)+len(extags))
	for _, v := range nodes {
		outs = append(outs, v.node)
		if v.nodeType != "urltest" && v.nodeType != "selector" {
			extTag = append(extTag, v.tag)
		}
	}
	extTag = append(extTag, extags...)
	outs = append(outs, extOut...)
	d, err := PatchMap(b, s, include, exclude, outs, extTag, true)
	if err != nil {
		return nil, fmt.Errorf("Patch: %w", err)
	}

	nodeTag := make([]string, 0, len(s)+len(extTag))

	for _, v := range s {
		if v.Ignored {
			continue
		}
		nodeTag = append(nodeTag, v.Tag)
	}
	nodeTag = append(nodeTag, extTag...)
	d, err = configUrlTestParser(d, nodeTag)
	if err != nil {
		return nil, fmt.Errorf("MakeConfig: %w", err)
	}

	bw := &bytes.Buffer{}
	jw := json.NewEncoder(bw)
	jw.SetIndent("", "    ")
	err = jw.Encode(d)
	if err != nil {
		return nil, fmt.Errorf("Patch: %w", err)
	}
	return bw.Bytes(), nil
}

func ToInsecure(c *clash.Clash) {
	for i := range c.Proxies {
		p := c.Proxies[i]
		p.SkipCertVerify = true
		c.Proxies[i] = p
	}
}

func PatchMap(
	tpl []byte,
	s []singbox.SingBoxOut,
	include, exclude string,
	extOut []interface{},
	extags []string,
	urltestOut bool,
) (map[string]any, error) {
	d := map[string]interface{}{}
	err := json.Unmarshal(tpl, &d)
	if err != nil {
		return nil, fmt.Errorf("PatchMap: %w", err)
	}
	tags := getTags(s)

	tags = append(tags, extags...)

	ftags := tags
	if include != "" {
		ftags, err = filter(true, include, ftags)
		if err != nil {
			return nil, fmt.Errorf("PatchMap: %w", err)
		}
	}
	if exclude != "" {
		ftags, err = filter(false, exclude, ftags)
		if err != nil {
			return nil, fmt.Errorf("PatchMap: %w", err)
		}
	}

	if urltestOut {
		s = append([]singbox.SingBoxOut{{
			Type:      "selector",
			Tag:       "select",
			Outbounds: append([]string{"urltest"}, tags...),
			Default:   "urltest",
		}}, s...)
		s = append(s, singbox.SingBoxOut{
			Type:      "urltest",
			Tag:       "urltest",
			Outbounds: ftags,
		})
	}

	s = append(s, singbox.SingBoxOut{
		Type: "direct",
		Tag:  "direct",
	})
	s = append(s, singbox.SingBoxOut{
		Type: "block",
		Tag:  "block",
	})
	s = append(s, singbox.SingBoxOut{
		Type: "dns",
		Tag:  "dns-out",
	})

	anyList := make([]any, 0, len(s)+len(extOut))
	for _, v := range s {
		anyList = append(anyList, v)
	}
	anyList = append(anyList, extOut...)

	d["outbounds"] = anyList

	return d, nil
}


func configUrlTestParser(config map[string]any, tags []string) (map[string]any, error) {
	outL := config["outbounds"].([]any)

	newOut := make([]any, 0, len(outL))

	for _, value := range outL {
		value := value

		outList := AnyGet[[]any](value, "outbounds")

		if len(outList) == 0 {
			newOut = append(newOut, value)
			continue
		}

		outListS := lo.FilterMap[any, string](outList, func(item any, index int) (string, bool) {
			s, ok := item.(string)
			return s, ok
		})

		tl, err := urlTestParser(outListS, tags)
		if err != nil {
			return nil, fmt.Errorf("customUrlTest: %w", err)
		}
		if tl == nil {
			newOut = append(newOut, value)
			continue
		}
		AnySet(&value, tl, "outbounds")
		newOut = append(newOut, value)
	}
	AnySet(&config, newOut, "outbounds")
	return config, nil
}

func AnyGet[K any](d any, f string) K {
	rv := reflect.ValueOf(d)
	rv = reflect.Indirect(rv)

	var k K

	switch rv.Type().Kind() {
	case reflect.Struct:
		f := rv.FieldByName(f)
		if !f.IsValid() {
			return k
		}
		d, ok := f.Interface().(K)
		if !ok {
			return k
		}
		return d
	case reflect.Map, reflect.Interface:
		m, ok := rv.Interface().(map[string]any)
		if !ok {
			return k
		}
		k, ok := m[f].(K)
		if !ok {
			return k
		}
		return k
	}
	return k
}


func AnySet(t, d any, f string) bool {
	rv := reflect.ValueOf(t)

	if rv.Kind() != reflect.Pointer {
		return false
	}

	rv = rv.Elem()
	rv = reflect.Indirect(rv)

	switch rv.Type().Kind() {
	case reflect.Struct:
		f := rv.FieldByName(f)
		if !f.IsValid() {
			return false
		}
		f.Set(reflect.ValueOf(d))

	case reflect.Map, reflect.Interface:
		m, ok := rv.Interface().(map[string]any)
		if !ok {
			return false
		}
		m[f] = d
	}
	return true
}


func urlTestParser(outbounds, tags []string) ([]string, error) {
	var include, exclude string
	extTag := []string{}

	for _, s := range outbounds {
		if strings.HasPrefix(s, "include: ") {
			include = strings.TrimPrefix(s, "include: ")
		} else if strings.HasPrefix(s, "exclude: ") {
			exclude = strings.TrimPrefix(s, "exclude: ")
		} else {
			extTag = append(extTag, s)
		}
	}

	if include == "" && exclude == "" {
		return nil, nil
	}

	tags, err := filterTags(tags, include, exclude)
	if err != nil {
		return nil, fmt.Errorf("urlTestParser: %w", err)
	}

	return lo.Union(append(extTag, tags...)), nil
}

func filterTags(tags []string, include, exclude string) ([]string, error) {
	nt, err := filter1(include, tags, true)
	if err != nil {
		return nil, fmt.Errorf("filterTags: %w", err)
	}
	nt, err = filter1(exclude, nt, false)
	if err != nil {
		return nil, fmt.Errorf("filterTags: %w", err)
	}
	return nt, nil
}

func filter1(reg string, tags []string, need bool) ([]string, error) {
	if reg == "" {
		return tags, nil
	}
	r, err := regexp.Compile(reg)
	if err != nil {
		return nil, fmt.Errorf("filter: %w", err)
	}
	tag := lo.Filter[string](tags, func(item string, index int) bool {
		has := r.MatchString(item)
		return has == need
	})
	return tag, nil
}