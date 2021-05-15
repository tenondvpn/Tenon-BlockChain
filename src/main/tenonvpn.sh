#!/bin/bash

check_sys(){
	if [[ -f /etc/redhat-release ]]; then
		release="centos"
	elif cat /etc/issue | grep -q -E -i "debian"; then
		release="debian"
	elif cat /etc/issue | grep -q -E -i "ubuntu"; then
		release="ubuntu"
	elif cat /etc/issue | grep -q -E -i "centos|red hat|redhat"; then
		release="centos"
	elif cat /proc/version | grep -q -E -i "debian"; then
		release="debian"
	elif cat /proc/version | grep -q -E -i "ubuntu"; then
		release="ubuntu"
	elif cat /proc/version | grep -q -E -i "centos|red hat|redhat"; then
		release="centos"
    fi
}

tenonvpn_path="/usr/local/tenonvpn"
date_now=`date +%s`
date_now=`expr $date_now / 3600`
if [[ $1 == "install" ]]
then
    rm -rf $tenonvpn_path
    mkdir -p $tenonvpn_path
    cp -rf ./local $tenonvpn_path
    cp -rf ./tenonvpn.sh /usr/bin/tenonvpn
    chmod 777 /usr/bin/tenonvpn

    ps -ef | grep tenonvpn_local | awk -F' ' '{print $2}' | xargs kill -9 > /dev/null 2>&1
    cp -rf $tenonvpn_path/local/proxychains.conf /etc/ > /dev/null 2>&1
    check_sys
    if [[ $release == "centos" ]]
    then
        cp -rf $tenonvpn_path/local/pkgs/tenonvpn_centos  $tenonvpn_path/local/tenonvpn_local
        cp -rf $tenonvpn_path/local/pkgs/redirect_centos  $tenonvpn_path/local/redirect
        cp -rf $tenonvpn_path/local/pkgs/libproxychains4.so_centos /usr/lib/libproxychains4.so
        cd $tenonvpn_path/local && nohup ./tenonvpn_local & > /dev/null 2>&1
    else
        cp -rf $tenonvpn_path/local/pkgs/tenonvpn_other  $tenonvpn_path/local/tenonvpn_local
        cp -rf $tenonvpn_path/local/pkgs/redirect_other  $tenonvpn_path/local/redirect
        cp -rf $tenonvpn_path/local/pkgs/libproxychains4.so_other /usr/lib/libproxychains4.so
        cd $tenonvpn_path/local && nohup ./tenonvpn_local & > /dev/null 2>&1
    fi

    echo $date_now > /var/tmp/tenon_day
    echo -e "\033[00;32minstall success.\033[0m\n"
    exit 0
fi

if [[ $1 == "remove" ]]
then
    ps -ef | grep tenonvpn_local | awk -F' ' '{print $2}' | xargs kill -9 > /dev/null 2>&1
    rm -rf $tenonvpn_path
    rm -rf /usr/bin/tenonvpn
    rm -rf /usr/lib/libproxychains4.so
    unset LD_PRELOAD
    echo -e "\033[00;32mremove success.\033[0m\n"
    exit 0
fi

if [[ $1 == "des" ]]
then
    des_country=$2
    valid_ct=("AQ" "BI" "CF" "TD" "CG" "RW" "ZR" "BZ" "CR" "SV" "GT" "HN" "MX" "NI" "PA" "KZ" "KG" "TJ" "TM" "UZ" "AT" "CZ" "HU" "LI" "SK" "CH" "CN" "JP" "KP" "KR" "TW" "HK" "MO" "DJ" "ER" "ET" "KE" "SO" "TZ" "UG" "BY" "EE" "LV" "LT" "MD" "PL" "UA" "KM" "MG" "MU" "YT" "RE" "SC" "CA" "GL" "PM" "US" "UM" "DZ" "EG" "LY" "MA" "SD" "TN" "EH" "MN" "RU" "DK" "FO" "FI" "IS" "NO" "SJ" "SE" "AS" "AU" "CK" "FJ" "PF" "GU" "KI" "MH" "FM" "NR" "NC" "NZ" "NU" "NF" "MP" "PW" "PG" "PN" "SB" "TK" "TO" "TV" "VU" "WF" "WS" "AR" "BO" "BR" "CL" "CO" "EC" "FK" "GF" "GY" "PY" "PE" "SR" "UY" "VE" "AF" "BD" "BT" "IN" "MV" "NP" "PK" "LK" "IO" "BV" "SH" "GS" "BN" "KH" "CX" "CC" "ID" "LA" "MY" "MM" "PH" "SG" "TH" "VN" "TP" "AL" "BA" "BG" "HR" "GR" "MK" "RO" "SI" "YU" "AM" "AZ" "BH" "CY" "GE" "IR" "IQ" "IL" "JO" "KW" "LB" "OM" "QA" "SA" "SY" "TR" "AE" "YE" "AD" "GI" "PT" "ES" "AO" "BW" "LS" "MW" "MZ" "NA" "ZA" "SZ" "ZM" "ZW" "VA" "IT" "MT" "SM" "TF" "HM" "AI" "AG" "AW" "BS" "BB" "BM" "VG" "KY" "CU" "DM" "DO" "GD" "GP" "HT" "JM" "MQ" "MS" "AN" "PR" "KN" "LC" "VC" "TT" "TC" "VI" "BJ" "BF" "CM" "CV" "CI" "GQ" "GA" "GM" "GH" "GN" "GW" "LR" "ML" "MR" "NE" "NG" "ST" "SN" "SL" "TG" "BE" "FR" "DE" "IE" "LU" "MC" "NL" "GB" "UK" "FX")
    for i in ${valid_ct[@]}
    do
       if [[ "$i" == "$des_country" ]]
       then
            echo $des_country > /var/tmp/tenon
            ps -ef | grep tenonvpn_local | awk -F' ' '{print $2}' | xargs kill -9 > /dev/null 2>&1
            cd $tenonvpn_path/local && nohup ./tenonvpn_local & > /dev/null 2>&1
            sleep 2
            tenonvpn curl ipinfo.io
            echo -e "\033[00;32mset destination country success."$des_country"\033[0m\n"
            exit 0
       fi
    done

    echo -e "\033[00;31mset destination country failed.\033[0m "$2"\n"
    exit 0
fi

started="`pidof tenonvpn_local`"
if [[ started == "" ]]
then
    ps -ef | grep tenonvpn_local | awk -F' ' '{print $2}' | xargs kill -9 > /dev/null 2>&1
    cp -rf $tenonvpn_path/local/proxychains.conf /etc/ > /dev/null 2>&1
    check_sys
    if [[ $release == "centos" ]]
    then
        cp -rf $tenonvpn_path/local/pkgs/tenonvpn_centos  $tenonvpn_path/local/tenonvpn_local
        cp -rf $tenonvpn_path/local/pkgs/redirect_centos  $tenonvpn_path/local/redirect
        cd $tenonvpn_path/local && nohup ./tenonvpn_local & > /dev/null 2>&1
    else
        cp -rf $tenonvpn_path/local/pkgs/tenonvpn_other  $tenonvpn_path/local/tenonvpn_local
        cp -rf $tenonvpn_path/local/pkgs/redirect_other  $tenonvpn_path/local/redirect
        cd $tenonvpn_path/local && nohup ./tenonvpn_local & > /dev/null 2>&1
    fi
    sleep 1
fi

status=`cat $tenonvpn_path/local/pristatus`
if [[ $status == "bwo" ]]
then
    buy_url=`cat $tenonvpn_path/local/url`
    echo -e "\033[00;31The bandwidth has been used up, please recharge or continue to use it tomorrow. Recharge link: \n"$buy_url"\n.\033[0m\n"
    > $tenonvpn_path/local/pristatus
    exit 0
fi

date_old=`cat /var/tmp/tenon_day`
if [[ "$date_now" != $date_old ]]
then
    ps -ef | grep tenonvpn_local | awk -F' ' '{print $2}' | xargs kill -9 > /dev/null 2>&1
    cp -rf $tenonvpn_path/local/proxychains.conf /etc/ > /dev/null 2>&1
    check_sys
    if [[ $release == "centos" ]]
    then
        cp -rf $tenonvpn_path/local/pkgs/tenonvpn_centos  $tenonvpn_path/local/tenonvpn_local
        cp -rf $tenonvpn_path/local/pkgs/redirect_centos  $tenonvpn_path/local/redirect
        cd $tenonvpn_path/local && nohup ./tenonvpn_local & > /dev/null 2>&1
    else
        cp -rf $tenonvpn_path/local/pkgs/tenonvpn_other  $tenonvpn_path/local/tenonvpn_local
        cp -rf $tenonvpn_path/local/pkgs/redirect_other  $tenonvpn_path/local/redirect
        cd $tenonvpn_path/local && nohup ./tenonvpn_local & > /dev/null 2>&1
    fi
    sleep 1
fi

if [[ $# -eq 1 ]]
then
    $tenonvpn_path/local/redirect $1
    echo
fi

if [[ $# -eq 2 ]]
then
    $tenonvpn_path/local/redirect $1 $2
    echo
fi

if [[ $# -eq 3 ]]
then
    $tenonvpn_path/local/redirect $1 $2 $3
    echo
fi

if [[ $# -eq 4 ]]
then
    $tenonvpn_path/local/redirect $1 $2 $3 $4
    echo
fi

if [[ $# -eq 5 ]]
then
    $tenonvpn_path/local/redirect $1 $2 $3 $4 $5
    echo
fi

if [[ $# -eq 6 ]]
then
    $tenonvpn_path/local/redirect $1 $2 $3 $4 $5 $6
    echo
fi

if [[ $# -eq 7 ]]
then
    $tenonvpn_path/local/redirect $1 $2 $3 $4 $5 $6 $7
    echo
fi

if [[ $# -eq 8 ]]
then
    $tenonvpn_path/local/redirect $1 $2 $3 $4 $5 $6 $7 $8
    echo
fi

if [[ $# -eq 9 ]]
then
    $tenonvpn_path/local/redirect $1 $2 $3 $4 $5 $6 $7 $8 $9
    echo
fi

if [[ $# -eq 10 ]]
then
    $tenonvpn_path/local/redirect $1 $2 $3 $4 $5 $6 $7 $8 $9 $10
    echo
fi