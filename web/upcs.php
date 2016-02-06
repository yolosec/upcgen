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

<h1>UPC UBEE EVW3226 WPA2 generator, from SSID</h1>
<form action="upcs.php" method="get">
    SSID: <input type="text" size="12" name="ssid" value="<?=(!isset($_REQUEST['ssid'])?'':htmlentities(trim($_REQUEST['ssid'])))?>">
    <input type="submit" value="Compute">
</form>
<br/>
<?php
$doCompute=true;
if (!isset($_REQUEST['ssid'])){
    $doCompute=false;
}

$ssid = trim($_REQUEST['ssid']);
if (strlen($ssid) > 7){
    $doCompute=false;
}

if ($doCompute){
    ?>

    <hr/>
    <h2>Results</h2>
<?php

$sql = 'SELECT * FROM wifi WHERE ssid=? ORDER BY mac;';

$db = new SQLite3('db/keys.db');
$statement = $db->prepare($sql);
$statement->bindValue(1, $ssid);

$result = $statement->execute();
$ctr = 0;
while($arr=$result->fetchArray(SQLITE3_ASSOC)) {
    $cmac = $arr['mac'];
    $ssid = $arr['ssid'];
    $pass = $arr['pass'];

    $inpass = '';
    if (isset($_REQUEST['pass'])){
        $inpass = ' value="'.htmlentities($_REQUEST['pass']).'" ';
    }

    printf("<div class=\"preformatted\">MAC: 647c34%s, SSID: UPC%s, PBKDF2(in=passphrase, salt=647c34%s, it=1000, cn=8) = %s "
        ."<input type=\"text\" name=\"pass_%d\" size=\"18\"%s>"
        ."<input type=\"button\" value=\"Derive Key\" onclick=\"derive_key(%d, '647c34%s', '%s')\"></div>\n",
        $cmac, $ssid, $cmac, $pass, $ctr, $inpass, $ctr, $cmac, $pass);

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
<div class="preformatted">MAC: 647c34000000, passwd: VAOUCAHR <a href="upcs.php?ssid=4543413&pass=VAOUCAHR">try</a></div>
<div class="preformatted">MAC: 647c34123456, passwd: HAYQQHCS <a href="upcs.php?ssid=3910551&pass=HAYQQHCS">try</a></div>
<div class="preformatted">MAC: 647c34fb7784, passwd: RFDPFBGQ <a href="upcs.php?ssid=0444024&pass=RFDPFBGQ">try</a></div>
<div class="preformatted">MAC: 647c34ffffff, passwd: HBEMKCOW <a href="upcs.php?ssid=9647852&pass=HBEMKCOW">try</a></div>
</body>
</html>

