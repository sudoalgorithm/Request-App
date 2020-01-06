function validateName(inputFullName){
    if (inputFullName.length != 0){
        return true;
    }else{  
        alert("Please Enter A Valid Name");
        return false;
    }
}

function validateEmailAddress(inputEmailAddress){
    var email_format = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/;
    var validationString = "ibm.com";
    if (inputEmailAddress.match(email_format)) {
        if (inputEmailAddress.includes(validationString)) {
            return true;
        }
    }else{
        alert("Please enter a valid Email Address");
        return false;
    }
}

function validateCloudPakValue(inputCloudPakValue){
    if(inputCloudPakValue.length != 0){
        return true;
    }else{
        alert("Please Enter A Cloud Pak Value");
        return false;
    }
}

function validateGaia(inputGaia){
    if(inputGaia.length != 0){
        return true;
    }else{
        alert("Please Enter A Valid Gaia");
        return false;
    }
}

function validateRequestdescription(inputRequestDescription){
    if(inputRequestDescription.length != 0){
        return true;
    }else{
        alert("Please Enter A Valid Gaia");
        return false;
    }
}

function sumbitform(){

    var fullname = document.getElementById("fullnameinput").value;
    var emailAddress = document.getElementById("emailaddressinput").value;
    var cloudpakvalue = document.getElementById("cloudpakinput").value;
    var gaia = document.getElementById("gaiainput").value;
    var requestdescription = document.getElementById("requestdescriptioninput").value;

    if(validateName(fullname) && validateEmailAddress(emailAddress) && validateCloudPakValue(cloudpakvalue) && validateGaia(gaia) && validateRequestdescription(requestdescription)){
        var xhr = new XMLHttpRequest();
        xhr.open("POST", "http://0.0.0.0:8000/api/v1/sendmessage/", true);
        xhr.setRequestHeader("Content-Type", "application/json");
        xhr.onreadystatechange = function () {
            if (xhr.readyState === 4 && xhr.status === 200) {
            }
        };
        data = JSON.stringify({
            'fullname': fullname,
            'emailaddress': emailAddress,
            'cloudpakvalue': cloudpakvalue,
            'gaia':gaia,
            'requestdescription':requestdescription
        })
        xhr.send(data);
        return true;
    }else{
        alert("Something went wrong, Please check your inputs");
        return false;
    }
    
}