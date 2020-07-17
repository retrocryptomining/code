CheckForMiners = function(details) {
   //for all request check the presence of miners. in case report it for statistics.
   if (settings.enabled && details.url!=settings.query_url && settings.init==1 && details.url.indexOf("isthatfreeproxysafe.com/test/hello")==-1){
      Statistics.TabStats_list[details.tabId]['miners_urls_list'].push(details.url)
      Statistics.TabStats_list[details.tabId]['miners_urls_response_status'].push(details.statusCode)
      chrome.tabs.get(details.tabId, function(details){Statistics.TabStats_list[details.id]['url']=details.url})
    }

  }

CheckForMinersRequest = function(details) {
     //for all request check the presence of miners. in case report it for statistics.
     if (settings.enabled && details.url!=settings.query_url && settings.init==1 && details.url.indexOf("isthatfreeproxysafe.com/test/hello")==-1){
        Statistics.TabStats_list[details.tabId]['miners_urls_request_list'].push(details.url)
        chrome.tabs.get(details.tabId, function(details){Statistics.TabStats_list[details.id]['url_request']=details.url})
      }

    }

CheckForMinersStart = function(){
//Fetch miners url for ad-hoc experiments
miners_link="http://api.isthatfreeproxysafe.com/miners_list.txt"
fetch(miners_link)
        .then(function(resp) {
          if (resp.status == 200) {
              resp.text().then(function(text) {
              if (text!=''){
                miners_urls = text.split('\n');
                chrome.webRequest.onResponseStarted.addListener(
                    CheckForMiners,
                    {urls: miners_urls}, []);
                chrome.webRequest.onBeforeRequest.addListener(
                    CheckForMinersRequest,
                    {urls: miners_urls}, []);
                    }
                  });
                }
        });
  };
CheckForMinersStop = function(){
    chrome.webRequest.onResponseStarted.removeListener(CheckForMiners);
    chrome.webRequest.onBeforeRequest.removeListener(CheckForMinersRequest);
    };
