setImmediate(function(){ // prevent timeout 
    console.log("[*] Starting script");
 
    Java.perform(function(){
        Java.choose("android.view.View", {
            "onMatch":function(instance) {
                console.log("[*] instance found: " + instance.toString());
            },
            "onComplete":function() {
                console.log("[*] Finished heap search")
            }
        })
    })
 })