package http_server

import "time"

func (c *HttpServer) purgeRoutine() {
	ticker := time.NewTicker(c.config.PurgeInterval)
	for {
		select {
		case <-c.stopPurgeRoutineCh:
			return
		case <-ticker.C:
		}

		c.mtx.Lock()
		c.mtx.Unlock()
	}
}
