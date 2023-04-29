package rkyz

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/marspere/goencrypt"
)

type RKRequest struct {
	Businessid       int    `json:"businessid"`
	Encrypttypeid    int    `json:"encrypttypeid"`
	Platformusercode string `json:"platformusercode"`
	Goodscode        string `json:"goodscode"`
	Inisoftkey       string `json:"inisoftkey"`
	Timestamp        int64  `json:"timestamp"`
	Sign             string `json:"sign"`
	Platformtypeid   int    `json:"platformtypeid"`

	Data string `json:"data"`

	Token        string `json:"token"`
	HeartbeatKey string `json:"heartbeat_key"`
	EndTime      string `json:"end_time"`

	MacCode     string `json:"mac_code"`
	RequestFlag string `json:"request_flag"`
	Version     string `json:"version"`

	Username string `json:"username"`

	Vars map[string]string `json:"vars"`

	Notice   string `json:"notice"`   //公告
	Basedata string `json:"basedata"` //基础数据
}

type RKResponse struct {
	Msg  string `json:"msg"`
	Data string `json:"data"`
	Code int    `json:"code"`
}

var (
	RKAPI     = "http://api.ruikeyz.com/netver/webapi"
	RKAPI2    = "http://api2.ruikeyz.com/netver/webapi"
	RKHandler *RKRequest
	CipherDES *goencrypt.CipherDES
)

var (
	Salt = "iamsalt"

	DESKey = []byte{}

	Platformusercode = ""

	Goodscode = ""
)

func init() {
	CipherDES = goencrypt.NewDESCipher(DESKey, nil, goencrypt.ECBMode, goencrypt.Pkcs7, goencrypt.PrintHex)
	RKHandler = &RKRequest{
		// 1：软件初始化      2：账号注册      3：账号登录      4：单码登录      5：心跳
		Businessid:       1,
		Encrypttypeid:    1,
		Platformusercode: Platformusercode,
		Goodscode:        Goodscode,
		Inisoftkey:       "", //初始化软件完后，接口会把此参数返回来，除“初始化软件”接口不需要此参数，其它所有接口都需要把此参数带上
		Timestamp:        0,  //毫秒
		Data:             "",
		Sign:             "",
		Platformtypeid:   1,

		MacCode:     "1234",
		RequestFlag: "1234",
		Version:     "v1.0",
		Vars:        make(map[string]string, 0),
	}

	RKHandler.MacCode = GetPhysicalID()
	// go RKHandler.Init()
}

func (r *RKRequest) Init() error {
	r.RequestFlag = strconv.FormatInt(time.Now().UnixMilli()<<5, 10)
	data := map[string]interface{}{
		"requestflag": r.RequestFlag,
		"maccode":     r.MacCode,
		"timestamp":   time.Now().UnixMilli(),
		"versionname": r.Version,
	}
	d, _ := json.Marshal(data)
	cipherText, _ := CipherDES.DESEncrypt(d)
	r.Data = cipherText

	resp, err := r.SignAndRequest()
	if err != nil {
		log.Println(err)
		return err
	}

	plain, err := CipherDES.DESDecrypt(resp.Data)
	if err != nil {
		log.Println(err)
		return err
	}

	type initResp struct {
		RequestFlag string `json:"requestflag"`
		Inisoftkey  string `json:"inisoftkey"`
		Softinfo    struct {
			Softname              string `json:"softname"`
			Consultwebsite        string `json:"consultwebsite"`
			Consultqq             string `json:"consultqq"`
			Consultwx             string `json:"consultwx"`
			Consulttel            string `json:"consulttel"`
			Opentestcount         int    `json:"opentestcount"`
			Opentestday           int    `json:"opentestday"`
			Logourl               string `json:"logourl"`
			Notice                string `json:"notice"`   //公告
			Basedata              string `json:"basedata"` //基础数据
			Newversionnum         string `json:"newversionnum"`
			Networkdiskurl        string `json:"networkdiskurl"`
			Diskpwd               string `json:"diskpwd"`
			Isforceupd            int    `json:"isforceupd"`
			Logintypeid           int    `json:"logintypeid"`
			Consumetypeid         int    `json:"consumetypeid"`
			Isoutsoftuser         int    `json:"isoutsoftuser"`
			Isbinding             int    `json:"isbinding"`
			Deductionconsumevalue int    `json:"deductionconsumevalue"`
			Maxloginnum           int    `json:"maxloginnum"`
		} `json:"softinfo"`
	}
	rp := &initResp{}
	err = json.Unmarshal([]byte(plain), rp)
	if err != nil {
		log.Println(err)
		return err
	}
	if r.RequestFlag != rp.RequestFlag {
		log.Println(err)
		return err
	}
	r.Inisoftkey = rp.Inisoftkey
	r.Basedata = rp.Softinfo.Basedata
	r.Notice = rp.Softinfo.Notice
	log.Printf("初始化结果：%s，基础信息：%s，公告：%s\n", resp.Msg, r.Basedata, r.Notice)
	return nil
}

func (r *RKRequest) Login(username, passwd string) (string, string, int) {
	r.Businessid = 3
	r.RequestFlag = strconv.FormatInt(time.Now().UnixMilli()<<5, 10)
	data := map[string]interface{}{
		"requestflag": r.RequestFlag,
		"maccode":     r.MacCode,
		"timestamp":   time.Now().UnixMilli(),
		"username":    username,
		"userpwd":     passwd,
	}
	d, _ := json.Marshal(data)
	cipherText, _ := CipherDES.DESEncrypt(d)
	r.Data = cipherText

	resp, err := r.SignAndRequest()
	if err != nil {
		log.Println(err)
		return "", "登录失败，请重试", -1
	}

	plain, err := CipherDES.DESDecrypt(resp.Data)
	if err != nil {
		log.Println("登录解密失败:", resp)
		return "", resp.Msg, resp.Code
	}

	type loginResp struct {
		RequestFlag  string `json:"requestflag"`
		Token        string `json:"token"`
		HeartbeatKey string `json:"heartbeatkey"`
		EndTime      string `json:"endtime"`
	}
	rp := &loginResp{}
	err = json.Unmarshal([]byte(plain), rp)
	if err != nil {
		log.Println(err)
	}

	if r.RequestFlag != rp.RequestFlag || rp.EndTime == "" || rp.HeartbeatKey == "" {
		log.Println("flag不一致、endtime or hearbeat key is nil，退出！", *rp)
		os.Exit(-1)
	}

	r.Token = rp.Token
	r.HeartbeatKey = rp.HeartbeatKey
	r.EndTime = rp.EndTime
	r.Username = username

	return r.Username, resp.Msg, resp.Code
}

// 单码验证
func (r *RKRequest) SingleCodeLogin(cardnum string) (string, int) {
	r.Businessid = 4
	r.RequestFlag = strconv.FormatInt(time.Now().UnixMilli()<<5, 10)
	data := map[string]interface{}{
		"requestflag": r.RequestFlag,
		"maccode":     r.MacCode,
		"timestamp":   time.Now().UnixMilli(),
		"cardnum":     cardnum,
	}
	d, _ := json.Marshal(data)
	cipherText, _ := CipherDES.DESEncrypt(d)
	r.Data = cipherText
	resp, err := r.SignAndRequest()
	if err != nil {
		return "", -1
	}
	plain, err := CipherDES.DESDecrypt(resp.Data)
	if err != nil {
		if resp.Msg == "单码到期" {
			log.Println("已到期,请联系代理商续费")
		} else {
			log.Println("错误:", resp.Msg)
		}
		return resp.Msg, resp.Code
	}
	type loginResp struct {
		RequestFlag  string `json:"requestflag"`
		Token        string `json:"token"`
		HeartbeatKey string `json:"heartbeatkey"`
		EndTime      string `json:"endtime"`
	}
	rp := &loginResp{}
	err = json.Unmarshal([]byte(plain), rp)
	if err != nil {
		log.Println(err)
	}
	if r.RequestFlag != rp.RequestFlag || rp.EndTime == "" || rp.HeartbeatKey == "" {
		fmt.Println("flag不一致、runtime or heartbeat key is nil，退出！", *rp)
		os.Exit(-1)
	}
	r.Token = rp.Token
	r.HeartbeatKey = rp.HeartbeatKey
	r.EndTime = rp.EndTime
	return resp.Msg, resp.Code
}

func (r *RKRequest) Register(username, passwd, qq string) (string, int) {
	r.Businessid = 2
	r.RequestFlag = strconv.FormatInt(time.Now().UnixMilli()<<5, 10)
	data := map[string]interface{}{
		"requestflag": r.RequestFlag,
		"maccode":     r.MacCode,
		"timestamp":   time.Now().UnixMilli(),
		"username":    username,
		"userpwd":     passwd,
		"qq":          qq,
	}
	d, _ := json.Marshal(data)
	cipherText, _ := CipherDES.DESEncrypt(d)
	r.Data = cipherText

	resp, err := r.SignAndRequest()
	if err != nil {
		log.Println("SignAndRequest失败", err)
		return resp.Msg, -1
	}

	plain, err := CipherDES.DESDecrypt(resp.Data)
	if err != nil {
		log.Println("des结果解密失败，resp:", err, resp.Msg)
		return resp.Msg, -1
	}

	type registerResp struct {
		RequestFlag     string `json:"requestflag"`
		ServerTimestamp int64  `json:"servertimestamp"`
	}
	rp := &registerResp{}
	err = json.Unmarshal([]byte(plain), rp)
	if err != nil {
		log.Println(err)
		return err.Error(), -1
	}
	if r.RequestFlag != rp.RequestFlag {
		log.Println("flag不一致，退出！")
		os.Exit(-1)
	}
	log.Println("注册结果：", resp.Msg, resp.Code)
	return resp.Msg, resp.Code
}

func (r *RKRequest) Heartbeat(username string) error {
	r.Businessid = 5
	r.RequestFlag = strconv.FormatInt(time.Now().UnixMilli()<<5, 10)
	data := map[string]interface{}{
		"requestflag":       r.RequestFlag,
		"maccode":           r.MacCode,
		"timestamp":         time.Now().UnixMilli(),
		"cardnumorusername": username,
		"token":             r.Token,
		"heartbeatkey":      r.HeartbeatKey,
	}
	d, _ := json.Marshal(data)
	cipherText, _ := CipherDES.DESEncrypt(d)
	r.Data = cipherText

	resp, err := r.SignAndRequest()
	if err != nil {
		log.Println(err)
		return err
	}

	plain, err := CipherDES.DESDecrypt(resp.Data)
	if err != nil {
		log.Println("des结果解密失败:resp=, err=", resp, err)
		return err
	}

	type heartbeatResp struct {
		RequestFlag     string `json:"requestflag"`
		ServerTimestamp int64  `json:"servertimestamp"`
		HeartbeatKey    string `json:"heartbeatkey"`
		EndTime         string `json:"endtime"`
	}
	rp := &heartbeatResp{}
	err = json.Unmarshal([]byte(plain), rp)
	if err != nil {
		log.Println(err)
		return err
	}
	r.HeartbeatKey = rp.HeartbeatKey
	r.EndTime = rp.EndTime
	log.Println("心跳结果：", resp.Msg, resp.Code)

	return nil
}

func (r *RKRequest) SignAndRequest() (rkResp *RKResponse, err error) {
	rkResp = &RKResponse{Code: -1, Msg: "内部错误，请再试一次"}
	plain := fmt.Sprintf("%v%v%v%v%v%v%v%v%v", r.Businessid, r.Encrypttypeid, r.Platformusercode, r.Goodscode, r.Inisoftkey, time.Now().UnixMilli(), r.Data, Salt, 1)
	// 签名算法(顺序不能变)：md5(businessID+encrypttypeid+platformusercode+softcode+inisoftkey+timestamp+data+signSalt+platformtypeid)
	signed, err := goencrypt.MD5(plain)
	if err != nil {
		log.Println(err)
		rkResp.Msg = err.Error()
		return
	}
	r.Sign = strings.ToLower(signed.UpperCase32())

	body := map[string]interface{}{
		"businessid":       r.Businessid,
		"encrypttypeid":    r.Encrypttypeid,
		"platformusercode": r.Platformusercode,
		"goodscode":        r.Goodscode,
		"inisoftkey":       r.Inisoftkey,
		"timestamp":        time.Now().UnixMilli(),
		"data":             r.Data,
		"sign":             r.Sign,
		"platformtypeid":   "1",
	}

	encoded, err := json.Marshal(&body)
	if err != nil {
		log.Println(err)
		rkResp.Msg = err.Error()
		return
	}

	request, _ := http.NewRequest(http.MethodPost, RKAPI, bytes.NewReader(encoded))

	request.Header.Set("Content-Type", "application/json;charset=UTF-8")
	request.Header.Set("Accept", "application/json, text/javascript, */*; q=0.01")
	request.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.108 Safari/537.36")

	http.DefaultClient.Timeout = time.Second * 5
	resp, err := http.DefaultClient.Do(request)
	if err != nil {
		log.Println("第一次请求失败，准备开始第二次，", err)
		request, _ = http.NewRequest(http.MethodPost, RKAPI2, bytes.NewReader(encoded))
		resp, err = http.DefaultClient.Do(request)
		if err != nil {
			log.Println("第二次post失败，", err)
			rkResp.Msg = err.Error()
			return
		}
	}
	rBody := new(bytes.Buffer)
	_, err = io.Copy(rBody, resp.Body)
	if err != nil {
		log.Println("SignAndRequest io.copy err:", err)
		rkResp.Msg = err.Error()
		return
	}

	err = json.Unmarshal(rBody.Bytes(), rkResp)
	if err != nil {
		log.Println(err)
		rkResp.Msg = err.Error()
		return
	}

	return
}

func (r *RKRequest) Recharge(account, card string) (string, int) {
	r.Businessid = 19
	r.RequestFlag = strconv.FormatInt(time.Now().UnixMilli()<<5, 10)
	data := map[string]interface{}{
		"requestflag":       r.RequestFlag,
		"maccode":           r.MacCode,
		"timestamp":         time.Now().UnixMilli(),
		"rechcardnum":       card,
		"cardnumorusername": account,
	}
	d, _ := json.Marshal(data)
	cipherText, _ := CipherDES.DESEncrypt(d)
	r.Data = cipherText

	resp, err := r.SignAndRequest()
	if err != nil {
		log.Println(err)
		return "充值失败，内部错误", -1
	}

	log.Println("充值结果：", resp.Msg, resp.Code)
	return resp.Msg, resp.Code
}

func (r *RKRequest) GetRemote(name string) (string, int) {
	r.Businessid = 8
	r.RequestFlag = strconv.FormatInt(time.Now().UnixMilli()<<5, 10)
	data := map[string]interface{}{
		"requestflag":       r.RequestFlag,
		"maccode":           r.MacCode,
		"timestamp":         time.Now().UnixMilli(),
		"token":             r.Token,
		"cardnumorusername": r.Username,
		"varname":           name,
	}
	d, _ := json.Marshal(data)
	cipherText, _ := CipherDES.DESEncrypt(d)
	r.Data = cipherText

	resp, err := r.SignAndRequest()
	if err != nil {
		log.Println("获取远程变量失败, code=, msg=, err=", resp.Code, resp.Msg, err.Error())
		return resp.Msg, resp.Code
	}

	plain, err := CipherDES.DESDecrypt(resp.Data)
	if err != nil {
		log.Println("远程变量解密失败，des结果解密失败：，resp=", err, resp)
		return resp.Msg, resp.Code
	}

	type getRemoteVarResp struct {
		RequestFlag     string `json:"requestflag"`
		ServerTimestamp int64  `json:"servertimestamp"`
		VarValues       []struct {
			VarName  string `json:"varname"`
			VarValue string `json:"varvalue"`
		} `json:"varlist"`
	}
	rp := &getRemoteVarResp{}
	err = json.Unmarshal([]byte(plain), rp)
	if err != nil {
		log.Println("远程变量Unmarshal失败, code=, msg=, err=", resp.Code, resp.Msg, err.Error())
	}
	if r.RequestFlag != rp.RequestFlag {
		log.Println("flag不一致，退出！")
		os.Exit(-1)
	}
	for _, v := range rp.VarValues {
		r.Vars[v.VarName] = v.VarValue
	}

	return resp.Msg, resp.Code
}

func (r *RKRequest) Logout(username string) int {
	r.Businessid = 7
	r.RequestFlag = strconv.FormatInt(time.Now().UnixMilli()<<5, 10)
	data := map[string]interface{}{
		"requestflag":       r.RequestFlag,
		"maccode":           r.MacCode,
		"timestamp":         time.Now().UnixMilli(),
		"token":             r.Token,
		"cardnumorusername": username,
	}
	d, _ := json.Marshal(data)
	cipherText, _ := CipherDES.DESEncrypt(d)
	r.Data = cipherText

	resp, err := r.SignAndRequest()
	if err != nil {
		log.Println("SignAndRequest失败", err, resp.Msg, resp.Code)
		return -1
	}

	log.Println("退出登录结果：", resp.Msg, resp.Code)
	return resp.Code
}
