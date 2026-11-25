(() => {
  const $ = (s, root=document) => root.querySelector(s);
  const $$ = (s, root=document) => [...root.querySelectorAll(s)];
  const KEY='stap_driver_demo_v1';
  const read=()=>{try{return JSON.parse(localStorage.getItem(KEY))||{users:[],orders:[],current:null}}catch{return {users:[],orders:[],current:null}}};
  let db=read(), selectedRole='customer', selectedMode='now', routeKm=0, routeText='', routeFare=10000;
  const save=()=>localStorage.setItem(KEY,JSON.stringify(db));
  const money=n=>Math.round(Number(n)||0).toLocaleString('hy-AM')+' ֏';
  const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

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
    const dashboardNav=$('#dashboardNav');if(dashboardNav)dashboardNav.hidden=!u;
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
  $('#openLoginHero')?.addEventListener('click',()=>openModal('loginModal'));
  $$('.modal-close').forEach(b=>b.addEventListener('click',()=>closeModal(b.closest('.modal').id)));
  $$('.modal').forEach(m=>m.addEventListener('click',e=>{if(e.target===m)closeModal(m.id)}));
  document.addEventListener('keydown',e=>{if(e.key==='Escape')$$('.modal.open').forEach(m=>closeModal(m.id))});
  function updateBookingTimeLimits(){
    const input=$('#scheduledAt'),now=new Date(),pad=n=>String(n).padStart(2,'0');
    const localValue=d=>d.getFullYear()+'-'+pad(d.getMonth()+1)+'-'+pad(d.getDate())+'T'+pad(d.getHours())+':'+pad(d.getMinutes());
    if(selectedMode==='now'){
      const max=new Date(now.getTime()+2*60*60*1000);
      input.min=localValue(now);input.max=localValue(max);
      $('#scheduledAtLabel').textContent='ՇՏԱՊ ՊԱՏՎԵՐԻ ԺԱՄԸ · ԱՅՍՕՐ՝ ՄՈՏԱԿԱ 1–2 ԺԱՄՈՒՄ';
      $('#scheduledAtHint').textContent='Ընտրեք այսօրվա ժամը․ թույլատրվում է միայն ներկա պահից մինչև առաջիկա 2 ժամը։';
      if(!input.value||input.value<input.min||input.value>input.max)input.value=localValue(new Date(Math.ceil(now.getTime()/60000)*60000+60*60000));
    }else{
      input.min=localValue(new Date(now.getTime()+15*60000));input.removeAttribute('max');
      $('#scheduledAtLabel').textContent='ՆԱԽՆԱԿԱՆ ՊԱՏՎԵՐԻ ԱՄՍԱԹԻՎ ԵՎ ԺԱՄ';
      $('#scheduledAtHint').textContent='Ընտրեք նախնական ամրագրման օրը և ժամը։';
      if(!input.value||input.value<input.min)input.value='';
    }
  }
  $('.mode-btn').forEach(b=>b.addEventListener('click',()=>{selectedMode=b.dataset.mode;$('.mode-btn').forEach(x=>x.classList.toggle('active',x===b));$('#scheduleFields').hidden=false;$('#scheduledAt').required=true;updateBookingTimeLimits();}));
  updateBookingTimeLimits();
  $('#serviceType').addEventListener('change',e=>{const v=e.target.value;$('#carSpecs').hidden=v!=='sober'; $('#destination').required=true;$('#bookingRateNote').textContent='Սակագին՝ 1 կմ = 1,000 ֏։ Վարորդը վարում է ձեր մեքենան։'});
  $$('.choice-btn').forEach(b=>b.addEventListener('click',()=>{const group=b.dataset.group;$$('.choice-btn[data-group="'+group+'"]').forEach(x=>x.classList.toggle('active',x===b));$('#'+(group==='transmission'?'transmissionType':'powerType')).value=b.dataset.value;}));
  $('#serviceType').dispatchEvent(new Event('change'));
  const MIN_FARE=10000, RATE_PER_KM=0;
  const districtNeighbors={
    'Աջափնյակ':['Արաբկիր','Դավթաշեն','Կենտրոն','Մալաթիա-Սեբաստիա'],
    'Ավան':['Արաբկիր','Նոր Նորք','Քանաքեռ-Զեյթուն'],
    'Արաբկիր':['Աջափնյակ','Ավան','Դավթաշեն','Կենտրոն','Քանաքեռ-Զեյթուն'],
    'Դավթաշեն':['Աջափնյակ','Արաբկիր'],
    'Էրեբունի':['Կենտրոն','Նորք-Մարաշ','Շենգավիթ','Նուբարաշեն'],
    'Կենտրոն':['Աջափնյակ','Արաբկիր','Նոր Նորք','Նորք-Մարաշ','Շենգավիթ','Քանաքեռ-Զեյթուն','Էրեբունի','Մալաթիա-Սեբաստիա'],
    'Մալաթիա-Սեբաստիա':['Աջափնյակ','Կենտրոն','Շենգավիթ'],
    'Նոր Նորք':['Ավան','Էրեբունի','Կենտրոն','Նորք-Մարաշ','Քանաքեռ-Զեյթուն'],
    'Նորք-Մարաշ':['Էրեբունի','Կենտրոն','Նոր Նորք'],
    'Նուբարաշեն':['Էրեբունի','Շենգավիթ'],
    'Շենգավիթ':['Էրեբունի','Կենտրոն','Մալաթիա-Սեբաստիա','Նուբարաշեն'],
    'Քանաքեռ-Զեյթուն':['Ավան','Արաբկիր','Կենտրոն','Նոր Նորք']
  };
  function districtDistance(from,to){
    if(from===to)return 0;
    const queue=[[from,0]],visited=new Set([from]);
    while(queue.length){
      const [current,distance]=queue.shift();
      for(const next of (districtNeighbors[current]||[])){
        if(next===to)return distance+1;
        if(!visited.has(next)){visited.add(next);queue.push([next,distance+1]);}
      }
    }
    return Infinity;
  }
  function calculateRoute(){
    const from=$('#pickupCommunity').value;
    const to=$('#destinationCommunity').value;
    if(!from||!to){
      routeKm=0;
      $('#routeResult').hidden=true;
      $('#routeHelp').textContent='Ընտրեք երկու համայնքները՝ նախնական արժեքը տեսնելու համար։';
      return false;
    }
    const distance=districtDistance(from,to);
    if(!Number.isFinite(distance)){
      routeKm=0;
      $('#routeResult').hidden=true;
      $('#routeHelp').textContent='Այս երթուղու արժեքը հնարավոր չեղավ հաշվարկել։';
      return false;
    }
    const intermediate=Math.max(0,distance-1);
    routeFare=distance<=1?MIN_FARE:12000+intermediate*1000;
    routeKm=1;
    routeText=distance===0?'Նույն համայնքի ներսում':distance===1?'Հարևան համայնքներ':intermediate+' միջանկյալ համայնք';
    $('#routeDistance').textContent=routeText;
    $('#routePrice').textContent=money(routeFare);
    $('#priceModalAmount').textContent=money(routeFare);
    $('#priceModalRoute').textContent=from+' → '+to+' · '+routeText;
    $('#routeResult').hidden=false;
    $('#routeHelp').textContent='Նախնական արժեքը հաշվարկվեց ըստ ընտրված համայնքների։ Հասցեները լրացրեք պատվերը պահպանելուց առաջ։';
    $('#bookingRateNote').textContent='Նախնական արժեք՝ '+money(routeFare)+'։ Սպասաժամ՝ 1 ժամ = 1,500 ֏ (առանձին)։';
    return true;
  }
  $('#calculateRoute')?.remove();
  $('#pickupCommunity').addEventListener('change',calculateRoute);
  $('#destinationCommunity').addEventListener('change',calculateRoute);
  calculateRoute();
  $('#bookingForm').addEventListener('submit',e=>{e.preventDefault();const u=user();if(!u){notify('Պատվեր ստեղծելու համար նախ գրանցվեք կամ մուտք գործեք։');openModal('loginModal');return}const f=new FormData(e.target),service=f.get('service');updateBookingTimeLimits();if(!f.get('scheduledAt')||f.get('scheduledAt')<$('#scheduledAt').min||($('#scheduledAt').max&&f.get('scheduledAt')>$('#scheduledAt').max)){notify(selectedMode==='now'?'Շտապ պատվերի ժամը պետք է լինի այսօր՝ առաջիկա 2 ժամվա ընթացքում։':'Նշեք վավեր ամսաթիվ և ժամ։');return}if(!calculateRoute()){notify('Նախ ընտրեք սկզբնակետի և նպատակակետի համայնքները։');return}if(!String(f.get('pickup')||'').trim()||!String(f.get('destination')||'').trim()){notify('Պատվերը պահպանելու համար լրացրեք երկու հասցեներն էլ՝ փողոց, շենք կամ օբյեկտի անուն։');(!String(f.get('pickup')||'').trim()?$('#pickup'):$('#destination')).focus();return}const order={id:'SD-'+Date.now(),customerId:u.id,orgId:u.role==='organization'?u.id:null,waitingRatePerHour:1500,from:f.get('pickupCommunity')+' · '+String(f.get('pickup')).trim(),to:f.get('destinationCommunity')+' · '+String(f.get('destination')).trim(),pickupCommunity:f.get('pickupCommunity'),destinationCommunity:f.get('destinationCommunity'),km:0,price:service==='sober'?routeFare:null,service,transmissionType:f.get('transmissionType')||'',powerType:f.get('powerType')||'',mode:selectedMode,scheduledAt:f.get('scheduledAt')||'',dateLabel:(selectedMode==='now'?'Շտապ՝ այսօր ':'Նախնական՝ ')+new Date(f.get('scheduledAt')).toLocaleString('hy-AM'),status:'Նոր հայտ',createdAt:new Date().toISOString()};db.orders.push(order);save();e.target.reset();routeKm=0;routeFare=10000;$('#routeResult').hidden=true;$('#bookingNotice').hidden=false;$('#bookingNotice').textContent='Հայտը պահպանվեց այս սարքի ցուցադրական համակարգում։ Իրական վարորդներին այն դեռ չի ուղարկվել։';notify('Ցուցադրական պատվերը ստեղծվեց։');setTimeout(()=>{showDashboard()},450)});
  $('#switchToLogin').onclick=()=>{closeModal('registerModal');openModal('loginModal')};
  $('#switchToRegister').onclick=()=>{closeModal('loginModal');switchAuth('customer')};
  $('#year').textContent=new Date().getFullYear();
  render();
})();
