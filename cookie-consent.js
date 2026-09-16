(()=>{
  const GA_ID='G-1XLV0DRBNH';
  const STORAGE_KEY='mgw_cookie_consent_v1';
  const MAX_AGE=180*24*60*60*1000;
  const banner=document.querySelector('[data-cookie-banner]');
  const panel=document.querySelector('[data-cookie-preferences]');
  const analyticsToggle=document.querySelector('#cookie-analytics');
  const manage=document.querySelector('[data-cookie-manage]');
  const status=document.querySelector('[data-cookie-status]');
  let analyticsLoaded=false;

  const readChoice=()=>{try{const value=JSON.parse(localStorage.getItem(STORAGE_KEY)||'null');return value&&Date.now()-value.savedAt<MAX_AGE?value:null}catch{return null}};
  const storeChoice=analytics=>localStorage.setItem(STORAGE_KEY,JSON.stringify({analytics,advertising:false,savedAt:Date.now()}));
  const updateConsent=analytics=>window.gtag('consent','update',{analytics_storage:analytics?'granted':'denied',ad_storage:'denied',ad_user_data:'denied',ad_personalization:'denied'});
  const loadAnalytics=()=>{
    if(analyticsLoaded)return;
    analyticsLoaded=true;
    const script=document.createElement('script');
    script.async=true;
    script.src=`https://www.googletagmanager.com/gtag/js?id=${GA_ID}`;
    document.head.appendChild(script);
    window.gtag('js',new Date());
    window.gtag('config',GA_ID,{allow_google_signals:false});
  };
  const removeAnalyticsCookies=()=>{
    document.cookie.split(';').map(v=>v.split('=')[0].trim()).filter(n=>n==='_ga'||n.startsWith('_ga_')).forEach(name=>{
      document.cookie=`${name}=; Max-Age=0; path=/; SameSite=Lax`;
      document.cookie=`${name}=; Max-Age=0; path=/; domain=.${location.hostname}; SameSite=Lax`;
    });
  };
  const applyChoice=(analytics,{announce=true}={})=>{
    updateConsent(analytics);
    if(analytics)loadAnalytics();else removeAnalyticsCookies();
    storeChoice(analytics);
    banner.hidden=true;panel.hidden=true;manage.hidden=false;
    if(announce&&status)status.textContent=analytics?'Preferenze salvate: cookie analitici accettati.':'Preferenze salvate: cookie analitici rifiutati.';
  };
  const openPreferences=()=>{const choice=readChoice();analyticsToggle.checked=Boolean(choice?.analytics);panel.hidden=false;banner.hidden=true;panel.querySelector('button')?.focus()};
  const closePreferences=()=>{panel.hidden=true;(readChoice()?manage:banner).hidden=false};

  document.querySelector('[data-cookie-accept]')?.addEventListener('click',()=>applyChoice(true));
  document.querySelector('[data-cookie-reject]')?.addEventListener('click',()=>applyChoice(false));
  document.querySelector('[data-cookie-customize]')?.addEventListener('click',openPreferences);
  document.querySelector('[data-cookie-save]')?.addEventListener('click',()=>applyChoice(analyticsToggle.checked));
  document.querySelector('[data-cookie-close]')?.addEventListener('click',closePreferences);
  manage?.addEventListener('click',openPreferences);
  panel?.addEventListener('keydown',event=>{if(event.key==='Escape')closePreferences()});

  const choice=readChoice();
  if(choice)applyChoice(Boolean(choice.analytics),{announce:false});
  else{banner.hidden=false;manage.hidden=true}
})();
