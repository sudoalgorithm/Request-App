function validateName(inputFullName){
    if (length(inputFullName) == 0){
        alert("Please Enter A Valid Name");
        return false;
    }else{  
        return true;
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

function validateGaia(inputGaia){
}

function requestdescription(inputRequestDescription){
}

function sumbitform(){
    var fullname = document.getElementById("fullnameinput").value;
    var emailAddress = document.getElementById("emailaddressinput").value;
    var cloudpakvalue = document.getElementById("cloudpakinput").value;
    var gaia = document.getElementById("gaiainput").value;
    var requestdescription = document.getElementById("requestdescriptioninput").value;
}