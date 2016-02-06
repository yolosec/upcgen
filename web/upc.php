<html>
<head>
    <title>UPC password generator UBEE EVW3226</title>
    <style>
        body,div,p,a,td,input {font-family: Arial, Helvetica, sans-serif; font-size: 10pt;}
        h1 {font-size: 14pt; }
        h2 {font-size: 12pt; }
        #footer {font-size: 8pt; text-align: center; padding: 0 10 10 10}
        #status {background-color: #C1C1FF; padding: 10 10 10 10; font-family: monospace;  white-space: pre;}
        .preformatted { font-family: monospace;  white-space: pre;}
    </style>
</head>
<body>

<h1>UPC UBEE EVW3226 WPA2 &amp; SSID generator</h1>
<form action="upc.php" method="get">
    MAC:
    647c34<input type="text" size="8" name="mac" value="<?=(!isset($_REQUEST['mac'])?'':htmlentities(trim($_REQUEST['mac'])))?>">
    <input type="submit" value="Compute">
</form>
<br/>
<?php
$doCompute=true;
if (!isset($_REQUEST['mac'])){
    $doCompute=false;
}

$mac = trim($_REQUEST['mac']);
if (strlen($mac) > 6){
    $doCompute=false;
}

if ($doCompute){
    ?>

    <hr/>
    <h2>Results</h2>
<?php
    $x = base_convert($mac,16,10);
    $macs=array();
    for($i=-7; $i<4; $i++){
        if ($x+$i < 0) continue;
        $macs[] = sprintf("%06s", base_convert($x+$i,10,16));
    }

    $inQuery = implode(',', array_fill(0, count($macs), '?'));
    $sql = 'SELECT * FROM wifi WHERE mac IN ('.$inQuery.') ORDER BY mac;';

    $db = new SQLite3('db/keys.db');
    $statement = $db->prepare($sql);
    foreach ($macs as $k => $id) {
        $statement->bindValue(($k + 1), $id);
    }

    $result = $statement->execute();
    $ctr = 0;
    while($arr=$result->fetchArray(SQLITE3_ASSOC)) {
        $cmac = $arr['mac'];
        $ssid = $arr['ssid'];
        $pass = $arr['pass'];

        $inpass = '';
        if (isset($_REQUEST['pass']) && $cmac === $mac){
            $inpass = ' value="'.htmlentities($_REQUEST['pass']).'" ';
        }

        $c = '   ';
        if ($ctr==4) $c = '2.4';
        if ($ctr==6) $c = '5  ';
        if ($cmac === $mac) $c = '-> ';

        printf("<div class=\"preformatted\">%s MAC: 647c34%s, SSID: UPC%s, PBKDF2(in=passphrase, salt=647c34%s, it=1000, cn=8) = %s "
               ."<input type=\"text\" name=\"pass_%d\" size=\"18\"%s>"
               ."<input type=\"button\" value=\"Derive Key\" onclick=\"derive_key(%d, '647c34%s', '%s')\"></div>\n",
            $c, $cmac, $ssid, $cmac, $pass, $ctr, $inpass, $ctr, $cmac, $pass);

        ++$ctr;
    }
?>
<br/>

<script src="sha1.js"></script>
<script src="pbkdf2.js"></script>
<script>
    function display_message(msg)
    {
        document.getElementById("status").innerHTML = msg;
    }

    function derive_key(ctr, salt, pass)
    {
        var password = document.getElementsByName('pass_'+ctr)[0].value;
        var iterations = 1000;
        var bytes = 8;

        // Sanity checks
        if (!password || !salt || !iterations || !bytes)
            return display_message("Please fill in your password to the text box");

        if (iterations < 0 || iterations > 10000)
            return display_message("Invalid number of iterations. The maximum is limited to 10000 for this demo.");

        if (bytes < 0 || bytes > 100)
            return display_message("Invalid number of bytes. The maximum is limit to 100 for this demo.");

        var mypbkdf2 = new PBKDF2(password, salt, iterations, bytes);
        var status_callback = function(percent_done) {
            display_message("Computed " + Math.floor(percent_done) + "%")};
        var result_callback = function(key) {
            display_message("PBKDF2(yours): " + key + "<br/>PBKDF2(pass):  " + pass + "<br/>Match: " + (key.localeCompare(pass) == 0 ? "OK" : "FAIL"))};
        mypbkdf2.deriveKey(status_callback, result_callback);
    }
</script>
Fill in your password to the textbox matching your SSID and press a button.<br/><br/>

Results:
<div id="status"></div>
<br/>
Or verify your password patch here <a href="http://anandam.name/pbkdf2/">online PBKDF2</a>.
<br/><br/>

<?php
}
?>
<h2>Test vectors</h2>
<div class="preformatted">MAC: 647c34000000, passwd: VAOUCAHR <a href="upc.php?mac=000000&pass=VAOUCAHR">try</a></div>
<div class="preformatted">MAC: 647c34123456, passwd: HAYQQHCS <a href="upc.php?mac=123456&pass=HAYQQHCS">try</a></div>
<div class="preformatted">MAC: 647c34fb7784, passwd: RFDPFBGQ <a href="upc.php?mac=fb7784&pass=RFDPFBGQ">try</a></div>
<div class="preformatted">MAC: 647c34ffffff, passwd: HBEMKCOW <a href="upc.php?mac=ffffff&pass=HBEMKCOW">try</a></div>
</body>
</html>

