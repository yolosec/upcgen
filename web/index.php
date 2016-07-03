<?php
if (isset($_REQUEST['ssid'])){
    $_REQUEST['ssid'] = str_replace("upc", "", strtolower($_REQUEST['ssid']));
}

$doCompute=true;
if (!isset($_REQUEST['ssid'])){
    $doCompute=false;
}

$ssid = trim($_REQUEST['ssid']);
if (strlen($ssid) > 7){
    $doCompute=false;
}
?>

<html>
<head>
    <title>UPC password generator UBEE EVW3226</title>
    <meta name="keywords" content="UBEE EVW3226 WPA2 password generator">
    <meta name="description" content="UPC password generator UBEE EVW3226 WPA2 default password recovery from SSID">
    <meta name="viewport" content="width=device-width, initial-scale=1, user-scalable=0">
    <link rel="stylesheet" type="text/css" href="bootstrap.css">
    <style>
        /*body,div,p,a,td,input {font-family: Arial, Helvetica, sans-serif; font-size: 10pt;}*/
        /*h1 {font-size: 14pt; }*/
        /*h2 {font-size: 12pt; }*/
        #footer {font-size: 8pt; text-align: center; padding: 0 10 10 10}
        #status {background-color: #C1C1FF; padding: 10 10 10 10; font-family: monospace;  white-space: pre;}
        .preformatted { font-family: monospace;  white-space: pre;}
    </style>
</head>
<body>

<div class="jumbotron text-center">
  <h1>UPC UBEE EVW3226 WPA2 generator</h1>
  <p>Generates default WPA2 WiFi passwords for UPC router UBEE EVW3226</p>
</div>

<div class="container">
    <div class="row">
        <div class="col-sm-12">
            <p>
            This generator helps to test your home router for vulnerability we found. Affected type is
            <a href="https://deadcode.me/static/ubee/ubee_front.jpg" rel="nofollow" target="_blank">UBEE EVW3226</a>.
            </p>

            <p>
            We generate candidate default WPA2 passwords from SSID (WiFi name). If none of generated password match
            your router is not vulnerable to this particular weakness.
            </p>

            <p>
            Enter numerical SSID part to the field below. Vulnerable SSID has typically the form
            <em>UPCxxxxxxx</em>, e.g., UPC2659797.
            </p>
        </div>
    </div>

    <div class="row">
        <div class="col-sm-12">
            <form action="index.php" method="get" role="form" class="form-inline">
                <div class="form-group">
                    <label for="ssid">SSID: </label>
                    UPC<input type="text" size="20" name="ssid" id="ssid" class="form-control" type="number" placeholder="2659797" value="<?=(!isset($_REQUEST['ssid'])?'':htmlentities(trim($_REQUEST['ssid'])))?>">
                </div>
                <input type="submit" value="Compute" class="btn btn-primary">
            </form>
        </div>
    </div>
<?php
if ($doCompute){
    ?>

    <hr/>
    <div class="row">
        <div class="col-sm-12">
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

    printf("<div class=\"preformatted\">MAC: 647c34%s, password: %s </div>\n", $cmac, $pass);
    ++$ctr;
}
?>
    <br/>
    <?php
    printf("Results: %d, lookup time: %0.6f s", $ctr, (microtime(true) - $mstart));
?>
        </div>
    </div>
<?php
}
?>

<hr/>

    <div class="row">
        <div class="col-sm-12">
            <p><small>Disclaimer: author has no responsibility on actions that may be caused by using this service. Do not break the law
            with this service or hack WiFis. It is only for educational / research purposes.</small></p>

            <p><small>
            We use pre-generated database for lookup. The database was generated for all MAC addresses with the prefix
            <em>64:7c:34</em> which corresponds to UBEE prefix. If you find another UBEE router with
            different prefix, please let us know, we will extend the database. Thanks!
            </small>
            </p>

            <p><a href="https://ubee.deadcode.me/db/keys.db">SQLite3 database with passwords 1.4 GB</a></p>

            <p><a href="https://deadcode.me/blog/2016/07/01/UPC-UBEE-EVW3226-WPA2-Reversing.html">Blog post about this vulnerability</a></p>
        </div>
    </div>
</div>

<script>
  (function(i,s,o,g,r,a,m){i['GoogleAnalyticsObject']=r;i[r]=i[r]||function(){
  (i[r].q=i[r].q||[]).push(arguments)},i[r].l=1*new Date();a=s.createElement(o),
  m=s.getElementsByTagName(o)[0];a.async=1;a.src=g;m.parentNode.insertBefore(a,m)
  })(window,document,'script','https://www.google-analytics.com/analytics.js','ga');

  ga('create', 'UA-80253845-1', 'auto');
  ga('send', 'pageview');

</script>
</body>
</html>

