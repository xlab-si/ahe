package com.example.arcadianiotdemo;

import androidx.appcompat.app.AppCompatActivity;

import android.content.Intent;
import android.os.Bundle;
import android.widget.TextView;

public class DisplayMessageActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_display_message);

        Intent intent = getIntent();
        String msg = intent.getStringExtra(MainActivity.EXTRA_MSG);
        String policy = intent.getStringExtra(MainActivity.EXTRA_POL);

        TextView textView = findViewById(R.id.textView);
        textView.setText("Policy:\n" + policy + "\n\nMessage:\n"+ msg);
    }
}