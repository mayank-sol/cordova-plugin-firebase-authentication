package by.chemerisuk.cordova.firebase;

import org.json.JSONException;
import org.json.JSONObject;

public class OTPResult {
    //region fields
    private boolean codeWasSent;
    private String idToken;
    private String verificationCode;
    //endregion

    //region constructor
    public OTPResult(String idToken, String verificationCode) {
        codeWasSent = verificationCode != null;
        this.idToken = idToken;
        this.verificationCode = verificationCode;
    }
    //endregion

    //region public methods
    public JSONObject toJson() throws JSONException {
        JSONObject result = new JSONObject();

        result.put("codeWasSent", codeWasSent);
        result.put("idToken", idToken == null ? JSONObject.NULL : idToken );
        result.put("verificationCode", verificationCode == null ? JSONObject.NULL : verificationCode );

        return result;
    }
    //endregion
}
