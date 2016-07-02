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
<form action="index.php" method="get">
    SSID: UPC<input type="text" size="20" name="ssid" placeholder="2659797" value="<?=(!isset($_REQUEST['ssid'])?'':htmlentities(trim($_REQUEST['ssid'])))?>">
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

$mstart = microtime(true);
$sql = 'SELECT * FROM wifi WHERE ssid=? ORDER BY mac;';

$db = new SQLite3('db/keys.db');
$statement = $db->prepare($sql);
$statement->bindValue(1, $ssid);

$result = $statement->execute();
$ctr = 0;
while($arr=$result->fetchArray(SQLITE3_ASSOC)) {
    $cmac = $arr['mac'];
    $ssid = $arr['ssid'];
    $pass = $arr['orig'];

    $inpass = '';
    if (isset($_REQUEST['pass'])){
        $inpass = ' value="'.htmlentities($_REQUEST['pass']).'" ';
    }

    printf("<div class=\"preformatted\">MAC: 647c34%s, SSID: UPC%s, password: %s </div>\n",
        $cmac, $ssid, $pass);

    ++$ctr;
}
?>
    <br/>
    <?php
    printf("Results: %d, lookup time: %0.6f s", $ctr, (microtime(true) - $mstart));

}
?>

</body>
</html>

