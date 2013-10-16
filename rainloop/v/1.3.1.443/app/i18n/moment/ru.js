// moment.js language configuration
// language : russian (ru)
// author : Viktorminator : https://github.com/Viktorminator
(function(){var a=[function(a){return a%10===1&&a%100!==11},function(a){return a%10>=2&&a%10<=4&&a%10%1===0&&(a%100<12||a%100>14)},function(a){return a%10===0||a%10>=5&&a%10<=9&&a%10%1===0||a%100>=11&&a%100<=14&&a%100%1===0},function(a){return!0}],b=function(b,c){var d=b.split("_"),e=Math.min(a.length,d.length),f=-1;while(++f<e)if(a[f](c))return d[f];return d[e-1]},c=function(a,c,d){var e={mm:"минута_минуты_минут_минуты",hh:"час_часа_часов_часа",dd:"день_дня_дней_дня",MM:"месяц_месяца_месяцев_месяца",yy:"год_года_лет_года"};return d==="m"?c?"минута":"минуту":a+" "+b(e[d],+a)},d=function(a,b){var c={nominative:"январь_февраль_март_апрель_май_июнь_июль_август_сентябрь_октябрь_ноябрь_декабрь".split("_"),accusative:"января_февраля_марта_апреля_мая_июня_июля_августа_сентября_октября_ноября_декабря".split("_")},d=/D[oD]? *MMMM?/.test(b)?"accusative":"nominative";return c[d][a.month()]},e=function(a,b){var c={nominative:"воскресенье_понедельник_вторник_среда_четверг_пятница_суббота".split("_"),accusative:"воскресенье_понедельник_вторник_среду_четверг_пятницу_субботу".split("_")},d=/\[ ?[Вв] ?(?:прошлую|следующую)? ?\] ?dddd/.test(b)?"accusative":"nominative";return c[d][a.day()]},f={months:d,monthsShort:"янв_фев_мар_апр_май_июн_июл_авг_сен_окт_ноя_дек".split("_"),weekdays:e,weekdaysShort:"вск_пнд_втр_срд_чтв_птн_сбт".split("_"),weekdaysMin:"вс_пн_вт_ср_чт_пт_сб".split("_"),longDateFormat:{LT:"HH:mm",L:"DD.MM.YYYY",LL:"D MMMM YYYY г.",LLL:"D MMMM YYYY г., LT",LLLL:"dddd, D MMMM YYYY г., LT"},calendar:{sameDay:"[Сегодня в] LT",nextDay:"[Завтра в] LT",lastDay:"[Вчера в] LT",nextWeek:function(){return this.day()===2?"[Во] dddd [в] LT":"[В] dddd [в] LT"},lastWeek:function(){switch(this.day()){case 0:return"[В прошлое] dddd [в] LT";case 1:case 2:case 4:return"[В прошлый] dddd [в] LT";case 3:case 5:case 6:return"[В прошлую] dddd [в] LT"}},sameElse:"L"},relativeTime:{future:"через %s",past:"%s назад",s:"несколько секунд",m:c,mm:c,h:"час",hh:c,d:"день",dd:c,M:"месяц",MM:c,y:"год",yy:c},ordinal:function(a){return"."}};typeof module!="undefined"&&module.exports&&(module.exports=f),typeof window!="undefined"&&this.moment&&this.moment.lang&&this.moment.lang("ru",f)})();