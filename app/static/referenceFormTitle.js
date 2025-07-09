$(function(){
	if (window.location.pathname.toLowerCase() == "/reference/") {
		console.log("yes");
		var urlParams = new URLSearchParams(window.location.search);
		if (urlParams.has('visit')) {
		  console.log("?");
		  $("#contentColumn").children('.title').children('h1').eq(0).text("Make an Appointment");
		} else {
		  console.log("???");
		  $("#contentColumn").children('.title').children('h1').eq(0).text("Request Materials");
		}
	}
});