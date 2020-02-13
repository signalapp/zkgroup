package org.signal.trevor;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;
import android.view.View;

import org.signal.zkgroup.ServerSecretParams;

import java.util.Arrays;

public final class MainActivity extends AppCompatActivity {

  private static final String TAG = "MainActivity";

  @Override
  protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    setContentView(R.layout.activity_main);
  }

  public void test(View view) {
    ServerSecretParams serverSecretParams = ServerSecretParams.generate();

    Log.d(TAG, String.format("Keypair contents: %s", Arrays.toString(serverSecretParams.serialize())));
  }
}
