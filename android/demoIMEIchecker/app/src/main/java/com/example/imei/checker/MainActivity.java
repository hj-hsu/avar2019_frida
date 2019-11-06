package com.example.imei.checker;

import androidx.appcompat.app.AppCompatActivity;

import android.content.Context;
import android.os.Bundle;
import android.telephony.TelephonyManager;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;

public class MainActivity extends AppCompatActivity {

    TextView mNetworkOP;
    TextView mSimPOP;
    TextView mDeviceID;
    Button mRefresh;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        setup_view();
        setup_controller();
        update_all();
    }

    protected void setup_view() {
        mNetworkOP = findViewById(R.id.network_op);
        mSimPOP = findViewById(R.id.sim_op);
        mDeviceID = findViewById(R.id.device_id);
        mRefresh = findViewById(R.id.btnRefresh);
    }

    protected void setup_controller() {
        mRefresh.setOnClickListener(clickListener);
    }

    private Button.OnClickListener clickListener = new Button.OnClickListener() {
        @Override
        public void onClick(View view) {
            switch (view.getId()) {
                case R.id.btnRefresh:
                    update_all();
                    break;
                default:
                    break;
            }
        }
    };

    protected void update_all() {
        /*
        java.lang.String android.telephony.TelephonyManager().getNetworkOperatorName()
        java.lang.String android.telephony.TelephonyManager().getSimOperatorName()
        java.lang.String android.telephony.TelephonyManager().getDeviceId()
        */
        TelephonyManager tm = (TelephonyManager) getSystemService(Context.TELEPHONY_SERVICE);
        String network_op_name = "";
        String sim_op_name = "";
        String device_id = "";
        try {
            network_op_name = tm.getNetworkOperatorName();
        } catch (Exception e) {
            Log.e("demo", e.getMessage());
        }
        try {
            sim_op_name = tm.getSimOperatorName();
        } catch (Exception e) {
            Log.e("demo", e.getMessage());
        }
        try {
            device_id = tm.getDeviceId();
        } catch (Exception e) {
            Log.e("demo", e.getMessage());
        }

        mNetworkOP.setText(network_op_name);
        mSimPOP.setText(sim_op_name);
        mDeviceID.setText(device_id);
    }
}
