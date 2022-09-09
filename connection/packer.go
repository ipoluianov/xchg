package connection

import (
	"archive/zip"
	"bytes"
	"io"
	"io/fs"
	"io/ioutil"
)

func PackBytes(data []byte) []byte {
	var err error
	buf := new(bytes.Buffer)
	zipWriter := zip.NewWriter(buf)
	var zipFile io.Writer
	zipFile, err = zipWriter.Create("data")
	if err == nil {
		_, err = zipFile.Write(data)
	}
	err = zipWriter.Close()
	return buf.Bytes()
}

func UnpackBytes(zippedData []byte) (result []byte, err error) {
	buf := bytes.NewReader(zippedData)
	var zipFile *zip.Reader
	zipFile, err = zip.NewReader(buf, buf.Size())
	if err != nil {
		return
	}
	var file fs.File
	file, err = zipFile.Open("data")
	if err == nil {
		result, err = ioutil.ReadAll(file)
		_ = file.Close()
	}
	return
}
