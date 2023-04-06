package com.newlibre.aescrypt

import android.os.Build
import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.util.Log
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import android.widget.Toast
import androidx.annotation.RequiresApi
import java.lang.Exception
import java.util.*

class MainActivity : AppCompatActivity() {

    lateinit var encryptButton : Button
    lateinit var decryptButton : Button
    lateinit var hmacButton : Button
    lateinit var hmacText : EditText
    lateinit var passwordText : EditText
    lateinit var clearText : EditText
    lateinit var ivText : EditText
    lateinit var crypton : Crypton

    lateinit var mainText : TextView;
    @RequiresApi(Build.VERSION_CODES.O)
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        encryptButton = findViewById(R.id.encryptButton)
        mainText = findViewById(R.id.mainText)
        passwordText = findViewById(R.id.passwordText)
        clearText = findViewById(R.id.clearText)
        ivText = findViewById(R.id.ivText)
        hmacButton = findViewById(R.id.hmacButton)
        hmacText = findViewById(R.id.hmacText)

        encryptButton.setOnClickListener {
            if (passwordText.text.toString().isEmpty()){
                Toast.makeText(applicationContext, "Please add a password & try again.",Toast.LENGTH_LONG).show()
            }
            else {
                crypton = Crypton(passwordText.text.toString(),
                    clearText.text.toString().toByteArray())
                var encryptedText = crypton.processData(ivText.text.toString())
                mainText.setText(
                    // call with true or blank -- true is default value
                    encryptedText
                )
                Log.d("Crypton", encryptedText)
            }
        }

        hmacButton.setOnClickListener {
            var Hmac = Crypton.generateHmac(passwordText.text.toString(),hmacText.text.toString())
            hmacText.setText(Hmac)
        }

        decryptButton = findViewById(R.id.decryptButton)
        decryptButton.setOnClickListener {
            if (passwordText.text.toString().isEmpty()){
                Toast.makeText(applicationContext, "Please add a password & try again.",Toast.LENGTH_LONG).show()
            }
            else {
                try {
                    val cipherBytes = Base64.getDecoder().decode(mainText.text.toString())
                    crypton = Crypton(passwordText.text.toString(),
                            cipherBytes)
                    var decryptedText = crypton.processData(ivText.text.toString(),false)
                    mainText.setText(decryptedText)
                    Log.d("Crypton", decryptedText)
                } catch (ex: Exception) {
                    Toast.makeText(
                        applicationContext,
                        "Could not decode (from Base64) the cipher bytes.",
                        Toast.LENGTH_LONG)
                        .show()
                }
            }
            //Toast.makeText(applicationContext, mainText.text.toString(),Toast.LENGTH_LONG).show()
            //Toast.makeText(applicationContext, cipherBytes.size.toString(),Toast.LENGTH_LONG).show()

        }
        passwordText.setText("c4747607e721580882e7186c136b22d9670779af296772a7abb76f0f40526644")
        ivText.setText("0fec978d93cb56afcc7665849f900bdb")
        mainText.setText("14P9L1h5eI8X2V7GQNdQnQeXWockfvqPJSyUZzTinSQ=")
    }

    fun BytesToHex(sha256HashKey : ByteArray) : String{
        var hex : String = ""
        for (i in sha256HashKey) {
            // Note: The capital X in the format string causes
            // the hex value to contain uppercase hex values (A-F)
            hex += String.format("%02X", i)
        }
        return hex;
    }
}