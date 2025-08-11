package internal

import (
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/mmcdole/gofeed"
)

type MonitorResult struct {
	Title     string
	Published time.Time
	Content   string
	IsNew     bool
}

// parseTimeFlexible 尝试使用多种常见时间格式进行解析，缺失时区时按 UTC 解析
func parseTimeFlexible(raw string) (time.Time, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return time.Time{}, fmt.Errorf("empty time string")
	}

	layouts := []string{
		time.RFC3339,
		time.RFC3339Nano,
		time.RFC1123,
		time.RFC1123Z,
		time.RFC822,
		time.RFC822Z,
		"Mon, 02 Jan 2006 15:04:05", // 无时区的 RFC1123 风格
		"2006-01-02 15:04:05",
		time.UnixDate,
		time.ANSIC,
		time.RubyDate,
	}
	loc, _ := time.LoadLocation("Asia/Shanghai")
	for _, layout := range layouts {
		if t, err := time.Parse(layout, trimmed); err == nil {
			return t, nil
		}
		if t, err := time.ParseInLocation(layout, trimmed, loc); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("unsupported time format: %q", raw)
}

// wrapHTMLFragment 将 HTML 片段包装为完整 HTML 文档
func wrapHTMLFragment(content string, title string) string {

	// 术语标准化映射
	replacements := map[string]string{
		"公债":  "国债",
		"两年期": "2年期",
		"日圆":  "日元",
	}

	for old, new := range replacements {
		content = strings.ReplaceAll(content, old, new)
	}

	if strings.TrimSpace(title) == "" {
		title = "Document"
	}
	return "<!DOCTYPE html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>" +
		title + "</title></head><body>" + content + "</body></html>"
}

// Monitor 解析 Atom/RSS 源并打印条目关键信息
func Monitor() MonitorResult {
	url := "http://192.168.2.88:8002/feed/all.rss"

	parser := gofeed.NewParser()
	feed, err := parser.ParseURL(url)
	if err != nil {
		fmt.Println("parse error:", err)
		return MonitorResult{}
	}

	if feed == nil {
		fmt.Println("empty feed")
		return MonitorResult{}
	}

	for _, item := range feed.Items {
		title := item.Title
		content := wrapHTMLFragment(item.Content, title)

		var published time.Time
		if item.PublishedParsed != nil {
			published = *item.PublishedParsed
		} else if item.UpdatedParsed != nil {
			published = *item.UpdatedParsed
		} else if t, perr := parseTimeFlexible(item.Published); perr == nil {
			published = t
		} else if t, uerr := parseTimeFlexible(item.Updated); uerr == nil {
			published = t
		} else {
			fmt.Println("parse time error:", perr)
			continue
		}

		if strings.Contains(title, "路透早报") && published.After(time.Now().Add(-24*time.Hour)) {
			log.Println("--------------------------------")
			log.Println("title:", title)
			log.Println("published time:", published.Format("2006-01-02 15:04:05"))
			log.Println("--------------------------------")

			return MonitorResult{
				Title:     title,
				Published: published,
				Content:   content,
				IsNew:     true,
			}
		}
	}

	return MonitorResult{}
}
