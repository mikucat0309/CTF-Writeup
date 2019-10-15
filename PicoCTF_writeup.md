# PicoCTF 2019


## Gerneral Skill

### mus1c

文字檔給的是名叫 Rockstar 的程式語言

丟進去 https://codewithrockstar.com 拿到 ascii code 再轉換一下就是flag

### 1_wanna_b3_a_r0ck5tar

這題多加了幾個判斷式，理解這語言後刪除以下語句並執行:

    Listen to the music             
    If the music is a guitar                  
    Say "Keep on rocking!"                
    Listen to the rhythm
    If the rhythm without Music is nothing

    Else Whisper "That ain't it, Chief"

得到ascii code 再轉換一下就是flag

## Forensic

### WhitePages

發現 E2 80 83 與 20 兩種組合

E2 80 83 代換成 0

20 代換成 1

![WhitePages](WhitePages.png)

---

## Reverse

### droids 0

關鍵java代碼

    public class FlagstaffHill {
        public static native String paprika(String str);

        public static String getFlag(String input, Context ctx) {
            Log.i("PICO", paprika(input));
            return "Not Today...";
        }
    }

用IDA Pro 查看 libhellojni.so 找到 paprika

很明顯paprika裡這段代表判斷成立會調用marjoram()否則回傳"try again"

    if ( v6 & 1 )
        v4 = (char *)marjoram();
    else
        v4 = "try again";

追進marjoram裡

    __int64 marjoram()
    {
    unsigned int v0; // eax
    char *v2; // [rsp+0h] [rbp-20h]

    v2 = strdup("notexist");
    v0 = strlen("notexist");
    return unscramble(&unk_1A1A, 35LL, v2, v0);
    }

再追進unscramble裡

    _BYTE *__fastcall unscramble(__int64 a1, int a2, __int64 a3, int a4)
    {
    int v5; // [rsp+10h] [rbp-30h]
    int i; // [rsp+14h] [rbp-2Ch]
    _BYTE *v7; // [rsp+18h] [rbp-28h]
    int v8; // [rsp+24h] [rbp-1Ch]
    __int64 v9; // [rsp+28h] [rbp-18h]

    v9 = a3;
    v8 = a4;
    v7 = calloc(a2, 1uLL);
    v5 = 0;
    for ( i = 0; i < a2; ++i )
        v7[i] = *(_BYTE *)(v9 + v5++ % v8) ^ *(_BYTE *)(a1 + i);
    return v7;
    }

scramble(str1_addr, str1_length, str2_addr, str2_length)

看起來是個XOR函數

回到marjoram，把&unk_1A1A與 "notexists"做XOR就得到flag了

### droids 1

    _BYTE *__fastcall anise(const char *a1)
    {
    unsigned int v1; // eax
    char *v3; // [rsp+0h] [rbp-20h]

    v3 = strdup(a1);
    v1 = strlen(a1);
    return unscramble((__int64)&unk_1A3E, 30LL, (__int64)v3, v1);
    }


這題把固定字串換成使用者輸入，但不知道要輸入什麼

可能需要一點通靈

已知flag前八個字元為"picoCTF{"，最後一個為"}"

![droids1](droids1.png)

嗯? input 那麼剛好最後一個字等於第二個字?

推測input七個字元去做XOR得到flag

### droids 2

    public class FlagstaffHill {
        public static native String sesame(String str);

        public static String getFlag(String input, Context ctx) {
            String[] witches = {"weatherwax", "ogg", "garlick", "nitt", "aching", "dismass"};
            int second = 3 - 3;
            int third = (3 / 3) + second;
            int fourth = (third + third) - second;
            int fifth = 3 + fourth;
            int sixth = (fifth + second) - third;
            String str = ".";
            if (input.equals("".concat(witches[fifth]).concat(str).concat(witches[third]).concat(str).concat(witches[second]).concat(str).concat(witches[sixth]).concat(str).concat(witches[3]).concat(str).concat(witches[fourth]))) {
                return sesame(input);
            }
            return "NOPE";
        }
    }

調用sesame之前還對input做檢查? 那input就確定是特定字串了

沒有意外跟前面一樣做XOR

    _BYTE *__fastcall oregano(const char *a1)
    {
    unsigned int v1; // eax
    char *v3; // [rsp+0h] [rbp-20h]

    v3 = strdup(a1);
    v1 = strlen(a1);
    return unscramble((__int64)&unk_1A5D, 39LL, (__int64)v3, v1);
    }


### droids 3

    public class FlagstaffHill {
        public static native String cilantro(String str);

        public static String nope(String input) {
            return "don't wanna";
        }

        public static String yep(String input) {
            return cilantro(input);
        }

        public static String getFlag(String input, Context ctx) {
            return nope(input);
        }
    }

開IDA Pro一路追到了sumac

    _BYTE *sumac()
    {
    unsigned int v0; // eax
    char *v2; // [rsp+0h] [rbp-20h]

    v2 = strdup("againmissing");
    v0 = strlen("againmissing");
    return unscramble((__int64)&unk_1A85, 26LL, (__int64)v2, v0);
    }

沒有意外跟前面一樣做XOR

### droids 4

    public class FlagstaffHill {
        public static native String cardamom(String str);

        public static String getFlag(String input, Context ctx) {
            String str = "aaa";
            StringBuilder ace = new StringBuilder(str);
            StringBuilder jack = new StringBuilder(str);
            StringBuilder queen = new StringBuilder(str);
            StringBuilder king = new StringBuilder(str);
            ace.setCharAt(0, (char) (ace.charAt(0) + 4));
            ace.setCharAt(1, (char) (ace.charAt(1) + 19));
            ace.setCharAt(2, (char) (ace.charAt(2) + 18));
            jack.setCharAt(0, (char) (jack.charAt(0) + 7));
            jack.setCharAt(1, (char) (jack.charAt(1) + 0));
            jack.setCharAt(2, (char) (jack.charAt(2) + 1));
            queen.setCharAt(0, (char) (queen.charAt(0) + 0));
            queen.setCharAt(1, (char) (queen.charAt(1) + 11));
            queen.setCharAt(2, (char) (queen.charAt(2) + 15));
            king.setCharAt(0, (char) (king.charAt(0) + 14));
            king.setCharAt(1, (char) (king.charAt(1) + 20));
            king.setCharAt(2, (char) (king.charAt(2) + 15));
            if (input.equals("".concat(queen.toString()).concat(jack.toString()).concat(ace.toString()).concat(king.toString()))) {
                return "call it";
            }
            return "NOPE";
        }
    }

這次沒有調用，不過這一串字串混淆+檢查提示了這題跟 droids 2類似

只不過這題的java代碼沒有調用罷了，完全不影響靜態分析XD

    _BYTE *__fastcall pepper(const char *a1)
    {
    unsigned int v1; // eax
    char *v3; // [rsp+0h] [rbp-20h]

    v3 = strdup(a1);
    v1 = strlen(a1);
    return unscramble((__int64)&unk_1AA0, 31LL, (__int64)v3, v1);
    }

沒有意外跟前面一樣做XOR

### Vault Door 3

    s = "jU5t_a_sna_3lpm13gc49_u_4_m0rf41"
    flag = []

    for i in range(32):
    flag.append("#")

    for i in range(8):
    flag[i] = s[i]

    for i in range(8,16):
    flag[23-i] = s[i]

    for i in range(16,32,2):
    flag[46-i] = s[i]

    for i in range(17,33,2):
    flag[i] = s[i]

    print("picoCTF{%s}" % "".join(flag))

### Vault Door 4

    myBytes = [
        106 , 85  , 53  , 116 , 95  , 52  , 95  , 98  ,
        0x55, 0x6e, 0x43, 0x68, 0x5f, 0x30, 0x66, 0x5f,
        98, 89, 116, 51, 115, 95, 50, 54,
        55, 101, 48, 51, 100, 49, 49, 54,
    ]
    flag = ""
    for b in myBytes:
        flag += chr(b)
    print("picoCTF{%s}" % flag)

### Vault Door 5

base64解碼後再URL解碼

![VaultDoor5](VaultDoor5.png)

### Vault Door 6

    myBytes = [
        0x3b, 0x65, 0x21, 0xa , 0x38, 0x0 , 0x36, 0x1d,
        0xa , 0x3d, 0x61, 0x27, 0x11, 0x66, 0x27, 0xa ,
        0x21, 0x1d, 0x61, 0x3b, 0xa , 0x2d, 0x65, 0x27,
        0xa , 0x63, 0x65, 0x64, 0x67, 0x37, 0x6d, 0x62,
    ]
    flag = []
    for b in myBytes:
        flag.append(chr(b ^ 0x55))

    print("picoCTF{%s}" % "".join(flag))

### Vault Door 7

    x = [
        1096770097,
        1952395366,
        1600270708,
        1601398833,
        1716808014,
        1734304823,
        962880562,
        895706419
    ]
    flag = ""
    for integer in x:
        s = hex(integer)[2:]
        s  = "0" * (8-len(s)) + s
        for i in range(0, 8, 2):
            ch = chr(int("0x"+s[i:i+2], 16))
            flag += ch

    print("picoCTF{%s}" % flag)

### Vault Door 8

    public static void main(String args[]) {
        char[] expected = { 0xF4, 0xC0, 0x97, 0xF0, 0x77, 0x97, 0xC0, 0xE4, 0xF0, 0x77, 0xA4, 0xD0, 0xC5, 0x77, 0xF4,
                0x86, 0xD0, 0xA5, 0x45, 0x96, 0x27, 0xB5, 0x77, 0x94, 0x85, 0xC0, 0xA5, 0xC0, 0xB4, 0xC2, 0xF0, 0xF0 };
        char[] plain = unscramble(expected);
        for (char c : plain) {
            System.out.print(c);
        }
    }

    public static char[] unscramble(char[] a) {
        for (int b = 0; b < a.length; b++) {
            char c = a[b];// 23670145
            c = switchBits(c, 3, 7);// 23650147
            c = switchBits(c, 2, 6);// 23450167
            c = switchBits(c, 3, 5);// 23410567
            c = switchBits(c, 2, 4);// 23014567
            c = switchBits(c, 1, 3);// 21034567
            c = switchBits(c, 0, 2);// 01234567
            a[b] = c;
        }
        return a;
    }