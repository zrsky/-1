//判断是否登录
function isLogin(owner,id){
	if(owner){
		mui.openWindow({
			id:id,
			url:id
		})
	}else{
		mui.confirm('','您还未登录，请先登录',['我知道了','现在去登录'],function(res){
							if(res.index == 1){
								mui.openWindow({
									id:"login_code.html",
									url:"login_code.html"
								})
							}
						},'div');
	}
}
function aaa(json){
  let arr1 = [];
  for (var key in json){
    arr1.push(key);
  }
  var sortArr = arr1.sort();
  var resultObj = {};
  for(var i =0;i<sortArr.length;i++){
    for(var key in json){
      if (key = sortArr[i]){
        resultObj = Object.assign(resultObj,{[key]:json[key]})
      }
    }
  }
  console.log(resultObj);
}
