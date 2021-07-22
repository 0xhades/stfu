package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"math/big"
	"math/rand"
	"os"
	"regexp"
	"strings"

	"github.com/dlclark/regexp2"
)

//TODO: apply sleep input

var (
	username, password string

	LikersPostID, FollowersTargetUsername, PostsTargetUsername, PostsHashtag, AccountsHashtag string

	proxies, toHide, toUnHide []string

	accounts []account

	multi, single bool

	PostsOfAccountsManagerStatus bool
	PostsOfHashtagManagerStatus  bool
	PostsOfExplorerManagerStatus bool

	AccountsOfFollowersManagerStatus bool
	AccountsOfHashtagManagerStatus   bool
	AccountsOfExplorerManagerStatus  bool
	AccountsOfLikersManagerStatus    bool
	AccountsOfListStatus             bool

	FollowAction  bool
	CommentAction bool
	LikeAction    bool

	defaultMillisecondsTimeout = 8000

	MillisecondsSleepBetweenEachPostActions    = 1200
	MillisecondsSleepBetweenEachGrab           = 2000
	MillisecondsSleepBetweenEachAccountActions = 5000
)

func main() {

	var err error

	clear()
	logo()
	Print("Coder: 0xhades", c, r, true)
	Print("Version: v1", c, r, true)
	println()

Retry:

	var Account *account
	var ok bool
	var choice string
	var All bool

	username, err = userInput("Username", c, r, r)
	check("Error while entering the username", err, false, r, c)

	password, err = userInput("Password", c, r, r)
	check("Error while entering the password", err, false, r, c)

	if Account, ok = newAccount(username, password, getProxy(), defaultMillisecondsTimeout); ok {
		printSuccess(fmt.Sprintf("%s logged in successfully", username), g, c)
	} else {
		errorPrint(fmt.Sprintf("Couldn't log into %s..", username), r, c)
		goto Retry
	}

	choice, err = userInput("Do you want to hide the story from all the senders? (y/n)", c, r, r)
	check("Error while entering The Choice", err, false, r, c)
	if YesOrNo(choice) {
		All = true
	}

	var oldest_cursor string
More:
	Total, Unseen, oldest_cursor, moreAvailable := Account.Messagers(oldest_cursor, getProxy(), defaultMillisecondsTimeout)
	if All {
		toHide = append(toHide, Total...)
	} else {
		toHide = append(toHide, Unseen...)
	}

	printDelete(fmt.Sprintf("Grabbed %d Messagers", len(toHide)), g, c)

	if moreAvailable {
		goto More
	}

	println()

	if len(toHide) <= 0 {
		errorPrint(fmt.Sprintf("Couldn't Grab any Messagers from Direct"), r, c)
		os.Exit(0)
	}

retryHiding:

	if len(toHide) < 50 {

		if Account.SetHideStory(toHide, false, getProxy(), defaultMillisecondsTimeout) {
			printSuccess(fmt.Sprintf("All the %d Users were Hide from story successfully", len(toHide)), g, c)
		} else {
			errorPrint(fmt.Sprintf("Couldn't Hide All %d Users, Retrying...", len(toHide)), r, c)
			goto retryHiding
		}

	} else {

		members_list := toHide
		members := len(members_list)
		group_limit := 50
		groups := 0
		var groups_list [][]string
		if members > group_limit {

			var group []string
			for i := 0; i < members; i++ {
				if i != 0 && i%group_limit == 0 {
					groups += 1
					groups_list = append(groups_list, group)
					group = []string{}
					if (members - (groups * group_limit)) < group_limit {
						break
					}
				}
				group = append(group, members_list[i])

			}

			left := (members - (groups * group_limit))

			group = []string{}
			for _, user := range getListInReverse(members_list, left) {
				group = append(group, user)
			}

			groups_list = append(groups_list, group)
			groups += 1

			for _, group := range groups_list {

				if Account.SetHideStory(group, false, getProxy(), defaultMillisecondsTimeout) {
					printSuccess(fmt.Sprintf("All the %d Users were Hide from story successfully", len(group)), g, c)
				} else {
					errorPrint(fmt.Sprintf("Couldn't Hide All %d Users, Retrying...", len(group)), r, c)
					goto retryHiding
				}

			}

		}

	}

}

func getListInReverse(s []string, count int) []string {
	var Items []string
	lastIndex := len(s) - 1
	for i := 0; i < count; i++ {
		Items = append(Items, s[lastIndex-i])
	}
	return Items
}

func appendToFile(filename string, data string) error {
	f, err := os.OpenFile(filename,
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.WriteString(data); err != nil {
		return err
	}
	return nil
}

func extractMultipleRegex2(patterns []string, text string, lengthLimit int) []string {
	var results []string
	for _, pattern := range patterns {
		re := regexp2.MustCompile(pattern, regexp2.None)
		var matches []string
		m, _ := re.FindStringMatch(text)
		for m != nil {
			result := m.GroupByNumber(1).String()
			if lengthLimit != 0 {
				if len(result) <= lengthLimit {
					matches = append(matches, result)
				}
			} else {
				matches = append(matches, result)
			}
			m, _ = re.FindNextMatch(m)
		}
		results = append(results, matches...)
	}

	return results
}

func extractRegex2(pattern string, text string, lengthLimit int) []string {
	re := regexp2.MustCompile(pattern, regexp2.None)

	var matches []string
	m, _ := re.FindStringMatch(text)
	for m != nil {
		result := m.GroupByNumber(1).String()
		if lengthLimit != 0 {
			if len(result) <= lengthLimit {
				matches = append(matches, result)
			}
		} else {
			matches = append(matches, result)
		}
		m, _ = re.FindNextMatch(m)
	}
	return matches

}

func extractMultipleRegex(patterns []string, text string) []string {
	var results []string
	for _, pattern := range patterns {
		r := regexp.MustCompile(pattern)
		for _, v := range r.FindAllStringSubmatch(text, -1) {
			results = append(results, v[1])
		}
	}
	return results
}

func extractRegex(pattern, text string) []string {
	var results []string
	r := regexp.MustCompile(pattern)
	for _, v := range r.FindAllStringSubmatch(text, -1) {
		results = append(results, v[1])
	}
	return results
}

func getCombo(filename string) ([]string, []string, error) {

	var list []string
	var password []string

	content, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, nil, err
	}

	lines := strings.Split(string(content), "\n")

	for _, line := range lines {

		raw := strings.Join(strings.Fields(line), "")
		raw = strings.Replace(raw, "\n", "", -1)
		raw = strings.Replace(raw, "\r", "", -1)
		raw = strings.Replace(raw, "\r\n", "", -1)
		raw = strings.Replace(raw, "\n\r", "", -1)
		raw = strings.Replace(raw, " ", "", -1)

		//combo := strings.SplitN(raw, ":", 2)
		combo := strings.Split(raw, ":")

		if len(combo) < 2 {
			continue
		}

		list = append(list, strings.ToLower(combo[0]))
		password = append(password, combo[1])
	}

	return list, password, nil

}

func getSessions(filename string) ([]string, []string, error) {

	/*sessionid:uid*/

	var sessionids []string
	var uids []string

	content, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, nil, err
	}

	lines := strings.Split(string(content), "\n")

	for _, line := range lines {

		raw := strings.Join(strings.Fields(line), "")
		raw = strings.Replace(raw, "\n", "", -1)
		raw = strings.Replace(raw, "\r", "", -1)
		raw = strings.Replace(raw, "\r\n", "", -1)
		raw = strings.Replace(raw, "\n\r", "", -1)
		raw = strings.Replace(raw, " ", "", -1)

		combo := strings.SplitN(raw, ":", 2)

		if len(combo) != 2 && len(combo) != 1 {
			continue
		}

		if len(combo) == 1 {
			_combo := strings.Split(raw, "%3A")
			sessionids = append(sessionids, combo[0])
			uids = append(uids, _combo[0])
		}

		if len(combo) == 2 {
			sessionids = append(sessionids, combo[0])
			uids = append(uids, combo[1])
		}

	}

	return sessionids, uids, nil

}

func saveSessions() error {

	/*sessionid:uid*/

	var sessions []string

	for _, account := range accounts {
		sessions = append(sessions, fmt.Sprintf("%s:%s", account.sessionID, account.uid))
	}

	if FileExist("sessions.txt") {
		if err := deleteFile("sessions.txt"); err != nil {
			return err
		}
	}

	if err := writeLines(sessions, "sessions.txt"); err != nil {
		return err
	}

	return nil

}

func FileExist(path string) bool {

	_, err := os.Open(path)
	if err != nil {
		return false
	}
	return true

}

func getProxies(filename string) ([]string, error) {

	var proxies []string
	var lines []string
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	lines = strings.Split(string(content), "\n")

	for _, line := range lines {

		rawProxy := strings.Join(strings.Fields(line), "")
		rawProxy = strings.Replace(rawProxy, "\n", "", -1)
		rawProxy = strings.Replace(rawProxy, "\r", "", -1)
		rawProxy = strings.Replace(rawProxy, "\r\n", "", -1)
		rawProxy = strings.Replace(rawProxy, "\n\r", "", -1)
		rawProxy = strings.Replace(rawProxy, " ", "", -1)

		if strings.Contains(rawProxy, ":") && strings.Contains(rawProxy, ".") &&
			!strings.Contains(rawProxy, " ") && rawProxy != "." {
			proxies = append(proxies, rawProxy)
		}

	}

	return proxies, nil

}

func getComments(filename string) ([]string, error) {

	var lines []string
	var list []string

	content, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	lines = strings.Split(string(content), "\n")

	for _, line := range lines {

		raw := strings.Replace(line, "\n", "", -1)
		raw = strings.Replace(raw, "\r", "", -1)
		raw = strings.Replace(raw, "\r\n", "", -1)
		raw = strings.Replace(raw, "\n\r", "", -1)

		raw = strings.Replace(raw, "#line", "%0D", -1)

		list = append(list, raw)

	}

	return list, nil

}

func getHashtags(filename string) ([]string, error) {

	var lines []string
	var list []string

	content, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	lines = strings.Split(string(content), "\n")

	for _, line := range lines {

		raw := strings.Join(strings.Fields(line), "")
		raw = strings.Replace(raw, "\n", "", -1)
		raw = strings.Replace(raw, "\r", "", -1)
		raw = strings.Replace(raw, "\r\n", "", -1)
		raw = strings.Replace(raw, "\n\r", "", -1)

		list = append(list, raw)

	}

	return list, nil

}

func removeFromAccountSlice(slice []account, index int) []account {
	return append(slice[:index], slice[index+1:]...)
}

func WriteToFile(filename string, data string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = io.WriteString(file, data)
	if err != nil {
		return err
	}
	return file.Sync()
}

func writeLines(lines []string, path string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	w := bufio.NewWriter(file)
	for _, line := range lines {
		_, _ = fmt.Fprintln(w, line)
	}
	return w.Flush()
}

func deleteFile(filename string) error {
	err := os.Remove(filename)
	if err != nil {
		return err
	}
	return nil
}

func urlToID(WebPostURL string) (string, error) {

	shortcode := strings.SplitN(WebPostURL, "/", 6)[4]
	code := string('A'*(12-len(shortcode))) + shortcode

	BytesCode := []byte(code)
	BytesCode = bytes.Replace(BytesCode, []byte("_"), []byte("/"), -1)
	BytesCode = bytes.Replace(BytesCode, []byte("-"), []byte("+"), -1)

	result, err := Base64ToInt(string(BytesCode))
	if err != nil {
		return "", err
	}

	number := result.Int64()
	if math.Signbit(float64(number)) {
		number = number * -1
	}

	return fmt.Sprintf("%d", number), nil

}

func Base64ToInt(s string) (*big.Int, error) {
	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	i := new(big.Int)
	i.SetBytes(data)
	return i, nil
}

func removeDuplicateStr(strSlice []string) []string {
	allKeys := make(map[string]bool)
	list := []string{}
	for _, item := range strSlice {
		if _, value := allKeys[item]; !value {
			allKeys[item] = true
			list = append(list, item)
		}
	}
	return list
}

func getProxy() string {
	if proxies != nil && len(proxies) > 0 {
		return proxies[rand.Intn(len(proxies))]
	}
	return ""
}
