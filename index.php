<?PHP
  require_once('bsecure.lib.php');
  
  $test = new BSecure();
  $test->CreateUser('test', 'test');
  $test->Logon('test', 'test');
  echo $test->Auth();
  $test->Logoff();
?>
