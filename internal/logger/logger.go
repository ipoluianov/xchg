package logger

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

var logsPath string
var loggerObject *log.Logger
var currentLogFileName string
var currentLogFile *os.File

var LogDepthDays = 30

func CurrentExePath() string {
	dir, _ := filepath.Abs(filepath.Dir(os.Args[0]))
	return dir
}

func Init(path string) {
	logsPath = path
	err := os.MkdirAll(path, 0777)
	if err != nil {
		fmt.Println("Can not create log directory")
	}
}

type FileInfo struct {
	Path           string
	Name           string
	Dir            bool
	NameWithoutExt string
	Ext            string
	Size           int64
	Date           time.Time
	Attr           string
}

func (c *FileInfo) SizeAsString() string {
	if c.Dir {
		return "<DIR>"
	}
	div := int64(1)
	uom := ""
	if c.Size >= 1024 {
		div = 1024
		uom = "KB"
	}
	if c.Size >= 1024*1024 {
		div = 1024 * 1024
		uom = "MB"
	}
	if c.Size >= 1024*1024*1024 {
		div = 1024 * 1024 * 1024
		uom = "GB"
	}

	result := strconv.FormatInt(c.Size/div, 10) + " " + uom
	return result
}

func GetDir(path string) ([]FileInfo, error) {
	result := make([]FileInfo, 0)
	files, err := ioutil.ReadDir(path)
	if err != nil {
		return result, err
	}

	dirsList := make([]FileInfo, 0)
	filesList := make([]FileInfo, 0)

	for _, f := range files {
		var fileInfo FileInfo
		if f.IsDir() {
			fileInfo.Name = f.Name()
		} else {
			fileInfo.Name = f.Name()
			fileInfo.Ext = filepath.Ext(f.Name())
			if len(fileInfo.Ext) > 0 {
				fileInfo.Ext = fileInfo.Ext[1:]
			}
		}

		fileInfo.NameWithoutExt = strings.TrimSuffix(fileInfo.Name, filepath.Ext(fileInfo.Name))
		fileInfo.Path = path + "/" + f.Name()
		fileInfo.Date = f.ModTime()
		fileInfo.Dir = f.IsDir()
		fileInfo.Size = f.Size()

		if f.IsDir() {
			dirsList = append(dirsList, fileInfo)
		} else {
			filesList = append(filesList, fileInfo)
		}
	}

	sort.Slice(dirsList, func(i, j int) bool {
		return dirsList[i].Name < dirsList[j].Name
	})

	sort.Slice(filesList, func(i, j int) bool {
		return filesList[i].Name < filesList[j].Name
	})

	for _, d := range dirsList {
		result = append(result, d)
	}

	for _, f := range filesList {
		result = append(result, f)
	}

	return result, nil
}

func CheckLogFile() {
	var err error
	logFile := logsPath + "/" + time.Now().Format("2006-01-02") + ".log"

	if logFile != currentLogFileName {
		if currentLogFile != nil {
			_ = currentLogFile.Close()
		}

		if loggerObject != nil {
			loggerObject = nil
		}

		currentLogFile, err = os.OpenFile(logFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
		if err != nil {
			fmt.Println("error opening file: ", err)
		}

		loggerObject = log.New(currentLogFile, "", log.Ldate|log.Lmicroseconds)
		time.Sleep(time.Millisecond * 500)
		currentLogFileName = logFile

		files, err := GetDir(logsPath)
		if err == nil {
			for _, file := range files {
				if !file.Dir {
					t, err := time.Parse("2006-01-02", file.NameWithoutExt)
					if err == nil {
						if time.Now().Sub(t) > time.Duration(LogDepthDays*24)*time.Hour {
							_ = os.Remove(file.Path)
						}
					}
				}
			}
		}
	}
}

func Println(v ...interface{}) {
	CheckLogFile()
	if loggerObject != nil {
		loggerObject.Println(v...)
	}
	fmt.Print(time.Now().UTC().Format("2006-01-02 15:04:05.999"), " ")
	fmt.Println(v...)
}

func Error(v ...interface{}) {
	CheckLogFile()
	if loggerObject != nil {
		loggerObject.Println(v...)
	}
	fmt.Print(time.Now().UTC().Format("2006-01-02 15:04:05.999"), " ")
	fmt.Println(v...)
}
