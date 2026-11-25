(() => {
  const $ = (s, root=document) => root.querySelector(s);
  const $$ = (s, root=document) => [...root.querySelectorAll(s)];
  const KEY='stap_driver_demo_v1';
  const read=()=>{try{return JSON.parse(localStorage.getItem(KEY))||{users:[],orders:[],current:null}}catch{return {users:[],orders:[],current:null}}};
  let db=read(), selectedRole='customer', selectedMode='now', routeKm=0, routeText='';
  const save=()=>localStorage.setItem(KEY,JSON.stringify(db));
  const money=n=>Math.round(Number(n)||0).toLocaleString('hy-AM')+' ֏';
  const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

  // Multilingual address autocomplete: Armenian, Russian and Latin input.
  const suggestTimers={pickup:null,destination:null};
  const suggestControllers={pickup:null,destination:null};
  const translit=(value,table)=>Array.from(value.toLowerCase()).map(ch=>table[ch]??ch).join('');
  const hyMap={'ա':'a','բ':'b','գ':'g','դ':'d','ե':'e','զ':'z','է':'e','ը':'y','թ':'t','ժ':'zh','ի':'i','լ':'l','խ':'kh','ծ':'ts','կ':'k','հ':'h','ձ':'dz','ղ':'gh','ճ':'ch','մ':'m','յ':'y','ն':'n','շ':'sh','ո':'o','չ':'ch','պ':'p','ջ':'j','ռ':'r','ս':'s','վ':'v','տ':'t','ր':'r','ց':'ts','ւ':'v','փ':'p','ք':'q','օ':'o','ֆ':'f','և':'ev'};
  const ruMap={'а':'a','б':'b','в':'v','г':'g','д':'d','е':'e','ё':'yo','ж':'zh','з':'z','и':'i','й':'y','к':'k','л':'l','м':'m','н':'n','о':'o','п':'p','р':'r','с':'s','т':'t','у':'u','ф':'f','х':'kh','ц':'ts','ч':'ch','ш':'sh','щ':'shch','ъ':'','ы':'y','ь':'','э':'e','ю':'yu','я':'ya'};
  const addressLanguage=q=>/[\u0530-\u058F]/.test(q)?'hy':/[\u0400-\u04FF]/.test(q)?'ru':'en';
  const queryVariants=q=>{
    const variants=[q];
    if(/[\u0530-\u058F]/.test(q)){
      variants.push(translit(q,hyMap));
      // Common Yerevan street names are expanded while the user is still typing.
      const prefix=q.toLowerCase().replace(/[\s-]+/g,'');
      const known={
        'աբո':'Աբովյան փողոց','աբով':'Աբովյան փողոց',
        'մաշ':'Մաշտոցի պողոտա','մաշտ':'Մաշտոցի պողոտա',
        'կոմ':'Կոմիտասի պողոտա','կոմի':'Կոմիտասի պողոտա',
        'բաղ':'Բաղրամյան պողոտա','բաղր':'Բաղրամյան պողոտա',
        'սայ':'Սայաթ-Նովայի պողոտա','սայա':'Սայաթ-Նովայի պողոտա',
        'ամի':'Ամիրյան փողոց','ամիր':'Ամիրյան փողոց'
      };
      if(known[prefix])variants.push(known[prefix],translit(known[prefix],hyMap));
    }
    if(/[\u0400-\u04FF]/.test(q))variants.push(translit(q,ruMap));
    return [...new Set(variants.map(v=>v.trim()).filter(Boolean))];
  };
  async function loadAddressSuggestions(id){
    const input=$('#'+id),list=$('#'+id+'Suggestions'),q=input.value.trim();
    if(!list)return;
    if(q.length<2){list.hidden=true;return}
    suggestControllers[id]?.abort();
    let controller=new AbortController();suggestControllers[id]=controller;
    list.innerHTML='<div class="suggestion-item"><span class="suggestion-main">Որոնում…</span></div>';
    list.hidden=false;
    try{
      // Search the typed fragment first, then add Yerevan context and transliterations.
      // One failed variant must not discard successful autocomplete results from the others.
      const variants=[...new Set(queryVariants(q).flatMap(term=>[term,term+' Yerevan']))];
      const photonTimer=setTimeout(()=>controller.abort(),9000);
      let responses;
      try{responses=await Promise.allSettled(variants.map(async term=>{
        const params=new URLSearchParams({q:term,limit:'10',lat:'40.1792',lon:'44.4991',zoom:'12',lang:addressLanguage(q)});
        const response=await fetch('https://photon.komoot.io/api/?'+params.toString(),{signal:controller.signal,headers:{Accept:'application/json'}});
        if(!response.ok)throw new Error('HTTP '+response.status);
        return response.json();
      }));}finally{clearTimeout(photonTimer)}
      if(input.value.trim()!==q)return;
      const seen=new Set(),items=[];
      responses.filter(result=>result.status==='fulfilled').forEach(result=>(result.value.features||[]).forEach(feature=>{
        const p=feature.properties||{},key=[p.name,p.street,p.housenumber,p.city,p.osm_type,p.osm_id].join('|').toLowerCase();
        if(!seen.has(key)){seen.add(key);items.push(feature)}
      }));
      // Empty Photon results must also trigger the backup provider (not only network errors).
      if(!items.length)throw new Error('No Photon autocomplete matches');
      list._items=items.slice(0,10);
      list.innerHTML=list._items.map((feature,index)=>{
        const p=feature.properties||{};
        const title=p.name||p.street||p.city||p.district||'Վայր';
        const address=[p.street&&p.name!==p.street?p.street:null,p.housenumber,p.district,p.city||'Երևան'].filter(Boolean).join(', ');
        const category=p.osm_value||p.osm_key||'Հասցե կամ վայր';
        return '<button type="button" class="suggestion-item" data-index="'+index+'"><span class="suggestion-main">'+esc(title)+'</span><span class="suggestion-sub">'+esc(address||category)+'</span></button>';
      }).join('');
      if(!list._items.length)list.innerHTML='<div class="suggestion-item"><span class="suggestion-main">Դեռ առաջարկներ չկան</span><span class="suggestion-sub">Շարունակեք գրել ևս մի քանի տառ կամ ավելացրեք փողոցի անունը։</span></div>';
      list.hidden=false;
    }catch(error){
      if(input.value.trim()!==q)return;
      if(error.name==='AbortError')return;
      console.warn('Photon autocomplete unavailable; trying Nominatim:',error);
      try{
        if(controller.signal.aborted){controller=new AbortController();suggestControllers[id]=controller;}
        const expanded=queryVariants(q).find(term=>term!==q&&/[\\u0530-\\u058F]/.test(term))||queryVariants(q).find(term=>term!==q)||q;
        const params=new URLSearchParams({q:expanded+', Yerevan, Armenia',format:'jsonv2',limit:'8',countrycodes:'am',addressdetails:'1',accept_language:addressLanguage(q),viewbox:'44.20,40.35,44.75,40.00'});
        const fallbackTimer=setTimeout(()=>controller.abort(),9000);
        let response;
        try{response=await fetch('https://nominatim.openstreetmap.org/search?'+params.toString(),{signal:controller.signal,headers:{Accept:'application/json'}})}finally{clearTimeout(fallbackTimer)}
        if(!response.ok)throw new Error('HTTP '+response.status);
        const results=await response.json();
        if(input.value.trim()!==q)return;
        list._items=(results||[]).map(item=>({
          geometry:{coordinates:[Number(item.lon),Number(item.lat)]},
          properties:{
            name:item.name||item.display_name?.split(',')[0]||'Վայր',
            street:item.address?.road||item.address?.pedestrian||'',
            housenumber:item.address?.house_number||'',
            district:item.address?.suburb||item.address?.city_district||'',
            city:item.address?.city||item.address?.town||item.address?.village||'Երևան',
            country:'Հայաստան',
            osm_value:item.type||'Հասցե'
          }
        }));
        list.innerHTML=list._items.map((feature,index)=>{
          const p=feature.properties||{};
          const title=p.name||p.street||p.city||'Վայր';
          const address=[p.street&&p.name!==p.street?p.street:null,p.housenumber,p.district,p.city||'Երևան'].filter(Boolean).join(', ');
          return '<button type="button" class="suggestion-item" data-index="'+index+'"><span class="suggestion-main">'+esc(title)+'</span><span class="suggestion-sub">'+esc(address||p.osm_value||'Հասցե')+'</span></button>';
        }).join('');
        if(!list._items.length)list.innerHTML='<div class="suggestion-item"><span class="suggestion-main">Հուշումներ չգտնվեցին</span><span class="suggestion-sub">Կարող եք շարունակել՝ գրելով ամբողջական հասցեն ձեռքով։</span></div>';
        list.hidden=false;
      }catch(fallbackError){
        if(input.value.trim()!==q)return;
        console.error('Address autocomplete fallback failed:',fallbackError);
        list.innerHTML='<div class="suggestion-item"><span class="suggestion-main">Հասցեի որոնումը չավարտվեց</span><span class="suggestion-sub">Ստուգեք ինտերնետ կապը կամ շարունակեք գրել ամբողջական հասցեն։</span></div>';
        list.hidden=false;
      }
    }
  }
  ['pickup','destination'].forEach(id=>{
    const input=$('#'+id),list=$('#'+id+'Suggestions');
    input.addEventListener('input',()=>{clearTimeout(suggestTimers[id]);suggestTimers[id]=setTimeout(()=>loadAddressSuggestions(id),300)});
    input.addEventListener('focus',()=>{if(input.value.trim().length>=2)loadAddressSuggestions(id)});
    input.addEventListener('keydown',e=>{if(e.key==='Escape')list.hidden=true});
    list.addEventListener('mousedown',e=>e.preventDefault());
    list.addEventListener('click',e=>{
      const button=e.target.closest('.suggestion-item');if(!button)return;
      const feature=list._items?.[Number(button.dataset.index)];if(!feature)return;
      const p=feature.properties||{},typedNumber=(input.value.match(/\d+[a-zա-ֆ]?/i)||[])[0];
      const street=p.street||p.name||'';
      const number=p.housenumber||typedNumber||'';
      const parts=[street,number,p.district,p.city||'Երևան',p.country||'Հայաստան'].filter(Boolean);
      input.value=[...new Set(parts)].join(', ');
      list.hidden=true;
      input.dispatchEvent(new Event('change',{bubbles:true}));
    });
    input.addEventListener('blur',()=>setTimeout(()=>{list.hidden=true},160));
  });

  const notify=(msg)=>{const n=$('#toast');n.textContent=msg;n.classList.add('show');setTimeout(()=>n.classList.remove('show'),3200)};
  const stars=n=>'★'.repeat(Math.max(0,Math.min(5,Math.round(n||0))))+'☆'.repeat(5-Math.max(0,Math.min(5,Math.round(n||0))));
  const user=()=>db.users.find(x=>x.id===db.current)||null;
  const roleLabel=r=>({customer:'Հաճախորդ',driver:'Վարորդ',organization:'Կազմակերպություն'}[r]||r);
  const statusLabel=s=>({'Նոր հայտ':'⏳ Սպասման մեջ','Սպասման մեջ':'⏳ Սպասման մեջ','Հաստատված':'✅ Հաստատված','Չեղարկված':'❌ Չեղարկված'}[s]||s);
  function openModal(id){$('#'+id).classList.add('open');document.body.classList.add('locked')}
  function closeModal(id){$('#'+id).classList.remove('open');if(!$('.modal.open'))document.body.classList.remove('locked')}
  function switchAuth(role){selectedRole=role||'customer';$$('[data-role]').forEach(b=>b.classList.toggle('active',b.dataset.role===selectedRole));$('#registerRoleName').textContent=roleLabel(selectedRole);$('#registerExtra').innerHTML=selectedRole==='driver'?'<label>Վարորդական իրավունքի տվյալներ<input name="license" required placeholder="Համար / սերիա"></label><label>Վարորդական փորձ<select name="experience"><option>Մինչև 1 տարի</option><option>1–3 տարի</option><option>3–5 տարի</option><option>5+ տարի</option></select></label>':selectedRole==='organization'?'<label>Կազմակերպության անվանում<input name="company" required placeholder="Կազմակերպության անվանումը"></label><label>ՀՎՀՀ<input name="tax" placeholder="ՀՎՀՀ"></label>':'<label>Ծննդյան ամսաթիվ<input name="birth" type="date"></label>';$('#loginModal').classList.remove('open');openModal('registerModal')}
  // Booking form is positioned near the top of the page, directly below the navigation.
  $$('#booking').forEach(section=>section.style.scrollMarginTop='96px');
  $$('a[href="#booking"]').forEach(a=>a.addEventListener('click',e=>{
    e.preventDefault();
    $('#booking').scrollIntoView({behavior:'smooth',block:'start'});
    setTimeout(()=>$('#pickup')?.focus({preventScroll:true}),450);
  }));
  function render(){
    const u=user();$('#navAuth').innerHTML=u?'<button class="nav-user" id="openDashboard"><span class="avatar">'+esc((u.company||u.name||'S').slice(0,1).toUpperCase())+'</span><span>'+esc(u.name||u.company)+'</span><b>Իմ էջը</b></button>':'<button class="nav-link" id="openLogin">Մուտք</button><button class="gold-btn small-btn" id="openRegister">Գրանցվել</button>';
    $('#navAuth').querySelector('#openDashboard')?.addEventListener('click',()=>showDashboard());
    $('#navAuth').querySelector('#openLogin')?.addEventListener('click',()=>openModal('loginModal'));
    $('#navAuth').querySelector('#openRegister')?.addEventListener('click',()=>switchAuth('customer'));
    $('#dashboardNav').hidden=!u;
  }
  function showDashboard(){
    const u=user();if(!u)return;
    const orders=db.orders.filter(o=>o.customerId===u.id||o.driverId===u.id||o.orgId===u.id);
    const received=db.orders.filter(o=>o.driverId===u.id&&o.ratingFromCustomer);
    const ratings=u.ratings||[];
    const avg=ratings.length?(ratings.reduce((a,b)=>a+b.score,0)/ratings.length).toFixed(1):'—';
    $('#dashboardContent').innerHTML='<div class="dash-top"><div><div class="eyebrow">ԱՆՁՆԱԿԱՆ ՏԱՐԱԾՔ</div><h2>'+esc(u.name||u.company)+'</h2><p>'+roleLabel(u.role)+' · '+esc(u.phone)+'</p></div><button class="outline-btn" id="logoutBtn">Դուրս գալ</button></div><div class="dash-grid"><article class="metric"><span>Վարկանիշ</span><strong>'+avg+' <small>/ 5</small></strong><em>'+stars(Number(avg)||0)+' · '+ratings.length+' գնահատական</em></article><article class="metric"><span>Հաշվեկշիռ</span><strong>'+money(u.balance||0)+'</strong><em>Առանձին հաշվեկշիռ</em></article><article class="metric"><span>Պատվերներ</span><strong>'+orders.length+'</strong><em>Ընդհանուր պատմություն</em></article></div><div class="dash-columns"><section class="panel"><div class="panel-head"><h3>Իմ պատվերները</h3><button class="text-gold" id="newOrderFromDash">+ Նոր պատվեր</button></div>'+(orders.length?orders.slice().reverse().map(o=>'<div class="order-row"><div><b>'+esc(o.from)+' → '+esc(o.to)+'</b><small>'+esc(o.dateLabel)+' · '+o.km+' կմ</small></div><strong>'+money(o.price)+'</strong><span class="status">'+esc(statusLabel(o.status))+'</span></div>').join(''):'<div class="empty-state">Դեռ պատվերներ չկան։ Ձեր առաջին պատվերը կարող եք ստեղծել այստեղից։</div>')+'</section><section class="panel"><div class="panel-head"><h3>Անձնական տվյալներ</h3><span class="secure-note">Պրոֆիլ</span></div><div class="profile-lines"><p><span>Անուն / կազմակերպություն</span><b>'+esc(u.name||u.company)+'</b></p><p><span>Էլ․ փոստ</span><b>'+esc(u.email)+'</b></p><p><span>Հեռախոս</span><b>'+esc(u.phone)+'</b></p><p><span>Հաշվի տեսակ</span><b>'+roleLabel(u.role)+'</b></p>'+(u.role==='driver'?'<p><span>Վարորդական տվյալներ</span><b>'+esc(u.license||'Նշված չէ')+'</b></p>':'')+(u.role==='organization'?'<p><span>ՀՎՀՀ</span><b>'+esc(u.tax||'Նշված չէ')+'</b></p>':'')+'</div><button class="outline-btn wide" id="editProfile">Խմբագրել տվյալները</button></section></div><div class="panel rating-panel"><div class="panel-head"><h3>Գնահատականներ</h3><span class="secure-note">1–5 աստղ</span></div><p class="muted">Հաճախորդներն ու վարորդները միմյանց գնահատում են ավարտված պատվերից հետո։ Այստեղ կցուցադրվեն ստացված կարծիքները։</p>'+(ratings.length?ratings.map(r=>'<div class="review"><b>'+stars(r.score)+'</b><span>'+esc(r.comment||'Գնահատական')+'</span></div>').join(''):'<div class="empty-state">Գնահատականներ դեռ չկան։ Ձեր վարկանիշը կձևավորվի իրական պատվերներից հետո։</div>')+'</div>';
    openModal('dashboardModal');
    $('#logoutBtn').onclick=()=>{db.current=null;save();closeModal('dashboardModal');render();notify('Դուք դուրս եք եկել հաշվից։')};
    $('#newOrderFromDash').onclick=()=>{closeModal('dashboardModal');$('#booking').scrollIntoView({behavior:'smooth',block:'start'})};
    $('#editProfile').onclick=()=>editProfile();
  }
  function editProfile(){const u=user();if(!u)return;$('#editProfileForm').innerHTML='<label>Անուն / կազմակերպության անվանում<input name="name" required value="'+esc(u.name||u.company||'')+'"></label><label>Հեռախոս<input name="phone" required value="'+esc(u.phone||'')+'"></label><label>Էլ․ փոստ<input name="email" type="email" required value="'+esc(u.email||'')+'"></label><button class="gold-btn wide" type="submit">Պահպանել</button>';openModal('editModal');$('#editProfileForm').onsubmit=e=>{e.preventDefault();const f=new FormData(e.target);u.name=f.get('name');if(u.role==='organization')u.company=u.name;u.phone=f.get('phone');u.email=f.get('email');save();closeModal('editModal');showDashboard();render();notify('Տվյալները պահպանվեցին այս սարքում։')}}
  async function digest(s){if(window.crypto?.subtle){const b=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(s));return [...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,'0')).join('')}return btoa(unescape(encodeURIComponent(s)))}
  $('#registerForm').addEventListener('submit',async e=>{e.preventDefault();const f=new FormData(e.target),email=String(f.get('email')).trim().toLowerCase();if(db.users.some(u=>u.email===email)){notify('Այս էլ․ փոստով հաշիվ արդեն կա։');return}const u={id:'u_'+Date.now(),role:selectedRole,name:f.get('name'),company:f.get('company')||'',phone:f.get('phone'),email,passwordHash:await digest(f.get('password')),license:f.get('license')||'',experience:f.get('experience')||'',tax:f.get('tax')||'',balance:0,ratings:[],createdAt:new Date().toISOString()};db.users.push(u);db.current=u.id;save();e.target.reset();closeModal('registerModal');render();notify('Հաշիվը ստեղծվեց ցուցադրական ռեժիմում։');showDashboard()});
  $('#loginForm').addEventListener('submit',async e=>{e.preventDefault();const f=new FormData(e.target),email=String(f.get('email')).trim().toLowerCase(),hash=await digest(f.get('password')),u=db.users.find(x=>x.email===email&&x.passwordHash===hash);if(!u){notify('Մուտքի տվյալները սխալ են։');return}db.current=u.id;save();closeModal('loginModal');render();showDashboard()});
  $$('.auth-role').forEach(b=>b.addEventListener('click',()=>switchAuth(b.dataset.role)));
  $('#openRegisterHero').onclick=()=>switchAuth('customer');
  $('#openLoginHero').onclick=()=>openModal('loginModal');
  $$('.modal-close').forEach(b=>b.addEventListener('click',()=>closeModal(b.closest('.modal').id)));
  $$('.modal').forEach(m=>m.addEventListener('click',e=>{if(e.target===m)closeModal(m.id)}));
  document.addEventListener('keydown',e=>{if(e.key==='Escape')$$('.modal.open').forEach(m=>closeModal(m.id))});
  $$('.mode-btn').forEach(b=>b.addEventListener('click',()=>{selectedMode=b.dataset.mode;$$('.mode-btn').forEach(x=>x.classList.toggle('active',x===b));$('#scheduleFields').hidden=selectedMode!=='scheduled';$('#scheduledAt').required=selectedMode==='scheduled';}));
  $('#serviceType').addEventListener('change',e=>{const v=e.target.value;$('#carSpecs').hidden=v!=='sober'; $('#destination').required=true;$('#calculateRoute').closest('.field').hidden=false;$('#bookingRateNote').textContent='Սակագին՝ 1 կմ = 1,000 ֏։ Վարորդը վարում է ձեր մեքենան։'});
  $$('.choice-btn').forEach(b=>b.addEventListener('click',()=>{const group=b.dataset.group;$$('.choice-btn[data-group="'+group+'"]').forEach(x=>x.classList.toggle('active',x===b));$('#'+(group==='transmission'?'transmissionType':'powerType')).value=b.dataset.value;}));
  $('#serviceType').dispatchEvent(new Event('change'));
  const MIN_FARE=5000, RATE_PER_KM=1000;
  // Yandex Geosuggest key: add the restricted browser key here after deployment.
  let routeRequest=0, addressTimer;
  async function calculateRoute(automatic=false){
    const a=$('#pickup').value.trim(),b=$('#destination').value.trim();
    if(!a||!b){if(!automatic)notify('Լրացրեք մեկնարկի և նպատակակետի հասցեները։');return}
    const requestId=++routeRequest,btn=$('#calculateRoute');
    btn.disabled=true;btn.textContent='Հաշվարկվում է…';
    $('#routeHelp').textContent='Հասցեները որոնվում են․ խնդրում ենք սպասել…';
    $('#routeResult').hidden=true;
    const fetchJson=async(url,timeout=12000)=>{
      const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),timeout);
      try{
        const response=await fetch(url,{signal:controller.signal,headers:{Accept:'application/json'}});
        if(!response.ok)throw Error('HTTP '+response.status);
        return await response.json();
      }finally{clearTimeout(timer)}
    };
    try{
      const geo=async(q)=>{
        const clean=q.replace(/,\s*(Հայաստան|Armenia|Հայաստանի Հանրապետություն)$/i,'').trim();
        const language=/[\u0530-\u058F]/.test(clean)?'hy':/[\u0400-\u04FF]/.test(clean)?'ru':'en';
        const variants=[clean,clean+', Yerevan',clean+', Armenia'];
        let photonError=null;
        for(const term of [...new Set(variants)]){
          try{
            const params=new URLSearchParams({q:term,limit:'8',lat:'40.1792',lon:'44.4991',zoom:'12',lang:language});
            const data=await fetchJson('https://photon.komoot.io/api/?'+params.toString());
            const features=(data.features||[]).filter(x=>x.geometry?.coordinates?.length===2);
            if(features.length){
              const inArmenia=features.filter(x=>{
                const p=x.properties||{};
                return /armenia|հայաստան|армения/i.test([p.country,p.countrycode,p.state,p.city,p.county].join(' '));
              });
              const pool=inArmenia.length?inArmenia:features;
              const chosen=pool.sort((x,y)=>{
                const xp=x.properties||{},yp=y.properties||{};
                const xs=(xp.city||'').toLowerCase().includes('yerevan')?0:1;
                const ys=(yp.city||'').toLowerCase().includes('yerevan')?0:1;
                return xs-ys;
              })[0];
              const [lon,lat]=chosen.geometry.coordinates;
              return {lon,lat};
            }
          }catch(error){photonError=error}
        }
        // Backup geocoder if Photon is unavailable or has no result.
        const params=new URLSearchParams({q:clean,format:'jsonv2',limit:'5',countrycodes:'am',addressdetails:'1',accept_language:language,viewbox:'44.20,40.35,44.75,40.00'});
        const fallback=await fetchJson('https://nominatim.openstreetmap.org/search?'+params.toString());
        if(fallback.length){
          const [lon,lat]=[Number(fallback[0].lon),Number(fallback[0].lat)];
          if(Number.isFinite(lon)&&Number.isFinite(lat))return {lon,lat};
        }
        if(photonError?.name==='AbortError')throw Error('Հասցեի որոնումը ուշանում է։ Փորձեք կրկին։');
        throw Error('Հասցեն չգտնվեց։ Գրեք փողոցի անունը և շենքի համարը կամ ընտրեք առաջարկվող հասցեն։');
      };
      const p=await geo(a);
      if(requestId!==routeRequest)return;
      $('#routeHelp').textContent='Մեկնարկի հասցեն գտնվեց․ որոնվում է նպատակակետը…';
      const d=await geo(b);
      if(requestId!==routeRequest)return;
      $('#routeHelp').textContent='Հասցեները գտնվեցին․ հաշվարկվում է մեքենայի երթուղին…';
      const routeUrl='https://router.project-osrm.org/route/v1/driving/'+p.lon+','+p.lat+';'+d.lon+','+d.lat+'?overview=false&alternatives=true&steps=false';
      const route=await fetchJson(routeUrl,18000);
      if(requestId!==routeRequest)return;
      if(route.code!=='Ok'||!route.routes?.length)throw Error('Այս հասցեների միջև մեքենայի երթուղի չգտնվեց։ Ստուգեք հասցեները։');
      const distance=route.routes[0].distance;
      if(!Number.isFinite(distance)||distance<=0)throw Error('Երթուղու հեռավորությունը հնարավոր չեղավ որոշել։');
      routeKm=Math.max(0.1,Math.round(distance/100)/10);
      const fare=Math.max(MIN_FARE,Math.round(routeKm*RATE_PER_KM));
      routeText='Երթուղի՝ '+routeKm+' կմ';
      $('#routeDistance').textContent=routeKm.toLocaleString('hy-AM')+' կմ';
      $('#routePrice').textContent=money(fare);
      $('#routeResult').hidden=false;
      $('#routeHelp').textContent='Հաշվարկը պատրաստ է։ Նվազագույն արժեքը՝ 5,000 ֏, սակագինը՝ 1,000 ֏/կմ։';
      if(!automatic)notify('Երթուղին և արժեքը հաշվարկվեցին։');
    }catch(err){
      if(requestId!==routeRequest)return;
      routeKm=0;
      $('#routeResult').hidden=true;
      $('#routeHelp').textContent=err.message||'Չհաջողվեց հաշվարկել երթուղին։ Ստուգեք հասցեները և կրկին փորձեք։';
      if(!automatic)notify(err.message||'Չհաջողվեց գտնել երթուղին։');
    }finally{
      if(requestId===routeRequest){btn.disabled=false;btn.textContent='Հաշվել երթուղին'}
    }
  }
  $('#calculateRoute').onclick=()=>calculateRoute(false);
  $('#calculateRoute').hidden=false;
  function scheduleRouteCalculation(){
    clearTimeout(addressTimer);routeRequest++;routeKm=0;$('#routeResult').hidden=true;
    const a=$('#pickup').value.trim(),b=$('#destination').value.trim();
    if(a&&b){$('#routeHelp').textContent='Երկու հասցեներն էլ լրացված են․ հաշվարկում ենք վերջնական արժեքը…';addressTimer=setTimeout(()=>calculateRoute(true),700)}
    else $('#routeHelp').textContent='Նշեք մեկնարկի և նպատակակետի հասցեները․ երկուսն էլ պարտադիր են։';
  }
  ['pickup','destination'].forEach(id=>{
    $('#'+id).addEventListener('input',scheduleRouteCalculation);
    $('#'+id).addEventListener('change',scheduleRouteCalculation);
  }); 
  $('#bookingForm').addEventListener('submit',e=>{e.preventDefault();const u=user();if(!u){notify('Պատվեր ստեղծելու համար նախ գրանցվեք կամ մուտք գործեք։');openModal('loginModal');return}const f=new FormData(e.target),service=f.get('service');if(!routeKm){notify('Նախ հաշվարկեք երթուղին։');return}const order={id:'SD-'+Date.now(),customerId:u.id,orgId:u.role==='organization'?u.id:null,waitingRatePerHour:1500,from:f.get('pickup'),to:f.get('destination'),km:routeKm,price:service==='sober'?Math.max(MIN_FARE,Math.round(routeKm*RATE_PER_KM)):null,service,transmissionType:f.get('transmissionType')||'',powerType:f.get('powerType')||'',mode:selectedMode,scheduledAt:f.get('scheduledAt')||'',dateLabel:selectedMode==='now'?'Շտապ՝ հիմա':new Date(f.get('scheduledAt')).toLocaleString('hy-AM'),status:'Նոր հայտ',createdAt:new Date().toISOString()};db.orders.push(order);save();e.target.reset();routeKm=0;$('#routeResult').hidden=true;$('#bookingNotice').hidden=false;$('#bookingNotice').textContent='Հայտը պահպանվեց այս սարքի ցուցադրական համակարգում։ Իրական վարորդներին այն դեռ չի ուղարկվել։';notify('Ցուցադրական պատվերը ստեղծվեց։');setTimeout(()=>{showDashboard()},450)});
  $('#switchToLogin').onclick=()=>{closeModal('registerModal');openModal('loginModal')};
  $('#switchToRegister').onclick=()=>{closeModal('loginModal');switchAuth('customer')};
  $('#year').textContent=new Date().getFullYear();
  render();
})();
