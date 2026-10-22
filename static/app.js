/* leakscope — klientsidans insamling.
   Varje collector har en grov entropi-uppskattning (bits) och en motåtgärd.
   Bitsiffrorna är indikativa, inte uppmätta mot din faktiska population. */

const $ = (s, r = document) => r.querySelector(s);
// Escapar även " och ' — annars kan ett besökarstyrt värde bryta ut ur ett
// HTML-attribut (t.ex. data-visit="…") och bli en äkta händelsehanterare.
const esc = (s) => String(s).replace(/[&<>"']/g, c => (
  { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const ok = (v) => (v !== undefined && v !== null && v !== '' ? v : '—');

/* En collector som hänger får inte blockera resten av sidan.
   Vissa API:er (ljud, WebRTC, röstlistor) svarar aldrig i vissa miljöer. */
function withTimeout(p, ms, label) {
  return Promise.race([
    Promise.resolve(p),
    new Promise(res => setTimeout(() => res('tidsgräns (' + ms + ' ms) — ' + label + ' svarade inte'), ms)),
  ]);
}

async function sha256(str) {
  if (window.crypto && crypto.subtle) {
    const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
    return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
  }
  // fallback utanför secure context (t.ex. http mot en LAN-adress)
  let h1 = 0x811c9dc5, h2 = 0x01000193;
  for (let i = 0; i < str.length; i++) {
    h1 = (h1 ^ str.charCodeAt(i)) >>> 0; h1 = Math.imul(h1, 16777619) >>> 0;
    h2 = (h2 + str.charCodeAt(i) * (i + 7)) >>> 0;
  }
  return (h1.toString(16) + h2.toString(16)).padStart(16, '0').repeat(4).slice(0, 64);
}

/* ------------------------------------------------------- förklaringar -- */
/* what: vad raden faktiskt är.  priv: hjälper privat läge?  why: varför.
   Privat läge ger en ny lagringsburk och raderar historik vid stängning. Det
   byter inte hårdvara, OS, skärm, teckensnitt eller nätverk — därför är svaret
   "nej" på nästan allt här. Hållet separat från COLLECTORS för att texterna
   ska gå att läsa och rätta som en sammanhängande tabell. */
const EXPLAIN = {
  ua: { what: 'Strängen webbläsaren presenterar sig med: produkt, version, motor och ofta OS.',
        priv: 'nej', why: 'Identisk sträng i privat läge — den beskriver programmet, inte sessionen.' },
  uach: { what: 'Samma sak som User-Agent men uppdelat i fält, där sajten kan be om extra detaljer som exakt version och CPU-arkitektur.',
          priv: 'nej', why: 'Lämnas ut likadant i privat läge.' },
  platform: { what: 'OS-plattform, antal CPU-kärnor och ungefärligt RAM — läst direkt från hårdvaran.',
              priv: 'nej', why: 'Hårdvaran är densamma oavsett fönstertyp.' },
  quirks: { what: 'Resultatet av några flyttalsberäkningar. Olika JS-motorer och ibland olika CPU:er ger olika sista decimaler.',
            priv: 'nej', why: 'Samma motor räknar likadant i privat läge.' },
  screen: { what: 'Skärmens upplösning, färgdjup och pixeltäthet.',
            priv: 'nej', why: 'Samma skärm. Privat läge ändrar ingen bildskärm.' },
  window: { what: 'Fönstrets inner- och yttermått. Skillnaden avslöjar bokmärkesfält, sidopaneler och vissa tillägg.',
            priv: 'delvis', why: 'Ett privat fönster öppnas ofta i standardstorlek och utan vissa fält — det kan skilja sig, men bara tills du ändrar storlek.' },
  tz: { what: 'Tidszon, språk och lokalformat, hämtat från operativsystemet.',
        priv: 'nej', why: 'Systemets klocka och språk är desamma.' },
  skew: { what: 'Hur mycket din klocka går fel jämfört med serverns.',
          priv: 'nej', why: 'Samma systemklocka.' },
  canvas: { what: 'En bild ritas osynligt och hashas. Små skillnader i GPU, drivrutin, typsnittsrendering och kantutjämning ger olika resultat.',
            priv: 'nej', why: 'Ritas av samma grafikstack. Undantaget är Brave, som slumpar canvas per session — även i vanligt läge.' },
  webgl: { what: 'Grafikkortets tillverkare och modell, läst rakt ur drivrutinen.',
           priv: 'nej', why: 'Samma GPU. Pekar ofta ut exakt hårdvarumodell.' },
  webglhash: { what: 'Ett fyrtiotal drivrutinsgränser och stödda tillägg, sammanfattade till en hash.',
               priv: 'nej', why: 'Samma drivrutin ger samma värden.' },
  audio: { what: 'En ton renderas i ljudstacken och summeras. Flyttalsresultatet skiljer sig mellan plattformar och byggen.',
           priv: 'nej', why: 'Samma ljudstack räknar likadant.' },
  fonts: { what: 'Vilka typsnitt som finns installerade, testat genom att mäta textbredd. Röjer installerad programvara och språkpaket.',
           priv: 'nej', why: 'Typsnitten är installerade i systemet, inte i sessionen.' },
  codecs: { what: 'Vilka ljud- och videoformat webbläsaren kan spela. Speglar OS-bygge och installerade codecpaket.',
            priv: 'nej', why: 'Samma codecs är installerade.' },
  voices: { what: 'Installerade talsyntesröster. Listan speglar OS, språkpaket och extra röstpaket.',
            priv: 'nej', why: 'Rösterna är installerade i systemet.' },
  plugins: { what: 'Kvarvarande plugin-lista och om en inbyggd PDF-visare finns.',
             priv: 'nej', why: 'Samma uppsättning i privat läge.' },
  webrtc: { what: 'WebRTC samlar nätverksadresser för direktanslutningar. Det kan röja din adress i det lokala nätet — och utan maskering din publika adress förbi en VPN-tunnel.',
            priv: 'delvis', why: 'mDNS-namnen (.local) slumpas per session, så värdet byter utseende. Själva nätverket och din riktiga adress är oförändrade.' },
  netinfo: { what: 'Uppkopplingens typ och ungefärliga hastighet enligt webbläsaren.',
             priv: 'nej', why: 'Samma uppkoppling.' },
  battery: { what: 'Batterinivå, laddningsstatus och uppskattad tid kvar.',
             priv: 'nej', why: 'Samma batteri. Firefox tog bort API:et helt.' },
  devices: { what: 'Antal kameror, mikrofoner och ljudutgångar. Antalet syns utan att du godkänner något; namnen kräver tillstånd.',
             priv: 'nej', why: 'Samma hårdvara är inkopplad.' },
  storage: { what: 'Hur mycket lagring sajten får ta. Kvoten är normalt en andel av ledigt diskutrymme.',
             priv: 'delvis', why: 'Kvoten kapas ofta hårt i privat läge — vilket i sig skvallrar om att du kör privat.' },
  perms: { what: 'Vilka behörigheter som är beviljade, nekade eller obesvarade. Mönstret är i sig spårbart.',
           priv: 'delvis', why: 'Behörigheter nollställs i privat läge, så mönstret skiljer sig — men ett nollställt mönster är också ett mönster.' },
  css: { what: 'Dina visningsval: mörkt läge, reducerad rörelse, kontrast- och pekdonsinställningar.',
         priv: 'nej', why: 'Systemets inställningar följer med.' },
  dnt: { what: 'Signalerna Do Not Track och Global Privacy Control, plus om automation upptäcks.',
         priv: 'nej', why: 'Samma inställningar. DNT ignoreras ändå i praktiken.' },
  // Serverns passiva rader
  'srv:ip': { what: 'Avsändaradressen paketen kom från. Servern kan inte svara utan den.',
              priv: 'nej', why: 'Privat läge rör inte nätverket. Bara VPN, Tor eller proxy döljer adressen.' },
  'srv:order': { what: 'I vilken ordning webbläsaren skickar sina headers, plus HTTP-version. Ordningen är klientspecifik.',
                 priv: 'nej', why: 'Samma klient skickar i samma ordning. Avslöjar dessutom en spoofad User-Agent.' },
  'srv:tls': { what: 'Fingeravtrycket av TLS-handskakningen: chiffersviter, extensions och kurvor i exakt den ordning din TLS-stack väljer.',
               priv: 'nej', why: 'Handskakningen är identisk. Den passerar dessutom oförändrad genom VPN och proxy.' },
  'srv:cookies': { what: 'Cookies och cachade ETag-värden som skickas tillbaka vid varje besök.',
                   priv: 'ja', why: 'Här hjälper privat läge på riktigt: en ny lagringsburk som töms när du stänger fönstret. Det är i stort sett det enda på hela sidan privat läge faktiskt åtgärdar.' },
};

const PRIV_LABEL = { nej: 'Privat läge: ingen skillnad', delvis: 'Privat läge: delvis',
                     ja: 'Privat läge: hjälper' };

function privBadge(key) {
  const ex = EXPLAIN[key];
  if (!ex) return '';
  return '<span class="priv p-' + ex.priv + '">' + PRIV_LABEL[ex.priv] + '</span>';
}

function tipAttrs(key) {
  const ex = EXPLAIN[key];
  if (!ex) return '';
  return ' data-tip="1" data-what="' + esc(ex.what) + '" data-priv="' + ex.priv
    + '" data-why="' + esc(ex.why) + '"';
}

/* Hovring på en rad förklarar vad den är och om privat läge biter. */
function attachTips(root) {
  const tip = $('#viztip');
  root.querySelectorAll('[data-tip]').forEach(el => {
    const show = (ev) => {
      tip.innerHTML = '<strong>' + esc(el.dataset.what) + '</strong>'
        + '<span class="t-priv p-' + el.dataset.priv + '">' + PRIV_LABEL[el.dataset.priv] + '</span>'
        + '<span class="t-why">' + esc(el.dataset.why) + '</span>';
      tip.setAttribute('aria-hidden', 'false');
      const w = 340;
      tip.style.left = Math.max(8, Math.min(ev.pageX + 14, scrollX + innerWidth - w - 8)) + 'px';
      tip.style.top = (ev.pageY + 16) + 'px';
    };
    el.addEventListener('mouseenter', show);
    el.addEventListener('mousemove', show);
    el.addEventListener('mouseleave', () => tip.setAttribute('aria-hidden', 'true'));
  });
}

/* ---------------------------------------------------------- collectors -- */
/* stable: räknas in i det sammansatta fingeravtrycket */

const COLLECTORS = [
  {
    group: 'Identitet & motor', id: 'ua', label: 'User-Agent', bits: 10, stable: true,
    fix: 'Tor Browser och Mullvad Browser harmoniserar strängen mot en stor grupp. Att "spoofa" den själv gör dig oftast mer unik, inte mindre.',
    run: () => navigator.userAgent,
  },
  {
    group: 'Identitet & motor', id: 'uach', label: 'User-Agent Client Hints (hög entropi)', bits: 8, stable: true,
    fix: 'Lämnas ut på begäran av sajten. Brave och Tor begränsar dem; Firefox och Safari implementerar dem inte alls.',
    run: async () => {
      if (!navigator.userAgentData) return 'stöds ej (Firefox/Safari)';
      try {
        const d = await navigator.userAgentData.getHighEntropyValues([
          'architecture', 'bitness', 'model', 'platformVersion',
          'uaFullVersion', 'fullVersionList', 'wow64']);
        return JSON.stringify(d);
      } catch (e) { return 'nekad: ' + e.message; }
    },
  },
  {
    group: 'Identitet & motor', id: 'platform', label: 'Plattform, kärnor, minne', bits: 6, stable: true,
    fix: 'Följer hårdvaran och OS. Svårt att dölja utan att sticka ut ännu mer. En VM med vanlig konfiguration sänker unikheten.',
    run: () => JSON.stringify({
      platform: navigator.platform,
      cores: navigator.hardwareConcurrency,
      memoryGB: navigator.deviceMemory,
      touchPoints: navigator.maxTouchPoints,
    }),
  },
  {
    group: 'Identitet & motor', id: 'quirks', label: 'JS-motorns matematiska avtryck', bits: 4, stable: true,
    fix: 'Avslöjar motor och ibland CPU- eller libm-version. Går i praktiken inte att dölja.',
    run: () => [Math.tan(-1e300), Math.sinh(1), Math.expm1(1), Math.pow(Math.PI, -100),
                (1337).toExponential(20)].join(' | '),
  },
  {
    group: 'Skärm & fönster', id: 'screen', label: 'Skärm', bits: 8, stable: true,
    fix: 'Tor Browsers "letterboxing" rundar fönsterstorleken till kvantiserade värden så att många användare hamnar i samma hink.',
    run: () => JSON.stringify({
      res: screen.width + '×' + screen.height,
      avail: screen.availWidth + '×' + screen.availHeight,
      colorDepth: screen.colorDepth,
      dpr: window.devicePixelRatio,
      orientation: screen.orientation && screen.orientation.type,
    }),
  },
  {
    group: 'Skärm & fönster', id: 'window', label: 'Fönsterstorlek (röjer verktygsfält och tillägg)', bits: 5, stable: false,
    fix: 'Skillnaden mellan outer och inner avslöjar bokmärkesfält, sidopaneler och vissa tillägg. Maximera inte om du vill smälta in.',
    run: () => JSON.stringify({
      inner: innerWidth + '×' + innerHeight,
      outer: outerWidth + '×' + outerHeight,
      chromeHeight: outerHeight - innerHeight,
    }),
  },
  {
    group: 'Plats & tid', id: 'tz', label: 'Tidszon och lokal', bits: 7, stable: true,
    fix: 'Röjer din grova geografi även bakom ett VPN i ett annat land — en klassisk läcka. Tor Browser rapporterar UTC.',
    run: () => {
      const r = Intl.DateTimeFormat().resolvedOptions();
      return JSON.stringify({
        timeZone: r.timeZone, locale: r.locale, calendar: r.calendar,
        numberingSystem: r.numberingSystem,
        utcOffsetMin: -new Date().getTimezoneOffset(),
        languages: navigator.languages,
      });
    },
  },
  {
    group: 'Plats & tid', id: 'skew', label: 'Klockavvikelse mot servern', bits: 2, stable: false,
    fix: 'Systemklockans drift är i sig ett svagt men beständigt id. NTP-synk minskar det.',
    run: () => (window.__serverSkewMs === undefined ? '—' : window.__serverSkewMs + ' ms'),
  },
  {
    group: 'Grafik', id: 'canvas', label: 'Canvas-fingeravtryck', bits: 10, stable: true,
    fix: 'Brave, Tor och Mullvad randomiserar eller blockerar utläsning av canvas. Det är den enskilt mest effektiva motåtgärden mot den här familjen av tekniker.',
    run: async () => {
      try {
        const c = document.createElement('canvas');
        c.width = 300; c.height = 60;
        const x = c.getContext('2d');
        x.textBaseline = 'top';
        x.font = '14px "Arial"';
        x.fillStyle = '#f60'; x.fillRect(0, 0, 100, 20);
        x.fillStyle = '#069'; x.fillText('leakscope \u{1F512} åäö', 2, 15);
        x.fillStyle = 'rgba(102,204,0,0.7)'; x.fillText('leakscope \u{1F512} åäö', 4, 25);
        x.globalCompositeOperation = 'multiply';
        x.beginPath(); x.arc(50, 40, 20, 0, Math.PI * 2); x.fill();
        return (await sha256(c.toDataURL())).slice(0, 32);
      } catch (e) { return 'blockerad: ' + e.message; }
    },
  },
  {
    group: 'Grafik', id: 'webgl', label: 'WebGL — grafikkort och drivrutin', bits: 11, stable: true,
    fix: 'Pekar ofta ut exakt GPU-modell och drivrutin. Brave randomiserar, Tor begränsar WebGL hårt.',
    run: () => {
      try {
        const gl = document.createElement('canvas').getContext('webgl');
        if (!gl) return 'ej tillgängligt';
        const dbg = gl.getExtension('WEBGL_debug_renderer_info');
        return JSON.stringify({
          vendor: dbg ? gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL) : gl.getParameter(gl.VENDOR),
          renderer: dbg ? gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL) : gl.getParameter(gl.RENDERER),
          version: gl.getParameter(gl.VERSION),
          shading: gl.getParameter(gl.SHADING_LANGUAGE_VERSION),
          maxTexture: gl.getParameter(gl.MAX_TEXTURE_SIZE),
          extensions: (gl.getSupportedExtensions() || []).length + ' st',
        });
      } catch (e) { return 'fel: ' + e.message; }
    },
  },
  {
    group: 'Grafik', id: 'webglhash', label: 'WebGL-parameteravtryck', bits: 6, stable: true,
    fix: 'Summan av ett fyrtiotal drivrutinsparametrar. Samma motåtgärder som ovan.',
    run: async () => {
      try {
        const gl = document.createElement('canvas').getContext('webgl');
        if (!gl) return '—';
        const keys = ['MAX_VERTEX_ATTRIBS', 'MAX_VARYING_VECTORS', 'MAX_RENDERBUFFER_SIZE',
          'MAX_VERTEX_UNIFORM_VECTORS', 'MAX_FRAGMENT_UNIFORM_VECTORS', 'MAX_VIEWPORT_DIMS',
          'ALIASED_LINE_WIDTH_RANGE', 'ALIASED_POINT_SIZE_RANGE', 'MAX_TEXTURE_IMAGE_UNITS',
          'MAX_CUBE_MAP_TEXTURE_SIZE', 'RED_BITS', 'DEPTH_BITS', 'STENCIL_BITS'];
        const v = keys.map(k => k + '=' + gl.getParameter(gl[k])).join(';')
          + ';ext=' + (gl.getSupportedExtensions() || []).join(',');
        return (await sha256(v)).slice(0, 32);
      } catch (e) { return '—'; }
    },
  },
  {
    group: 'Ljud', id: 'audio', label: 'AudioContext-fingeravtryck', bits: 7, stable: true,
    fix: 'Avslöjar hur ljudstacken räknar flyttal. Brave och Tor lägger till brus som bryter avtrycket.',
    run: async () => {
      try {
        const Ctx = window.OfflineAudioContext || window.webkitOfflineAudioContext;
        if (!Ctx) return 'ej tillgängligt';
        const ctx = new Ctx(1, 44100, 44100);
        const osc = ctx.createOscillator();
        osc.type = 'triangle'; osc.frequency.value = 10000;
        const comp = ctx.createDynamicsCompressor();
        comp.threshold.value = -50; comp.knee.value = 40; comp.ratio.value = 12;
        comp.attack.value = 0; comp.release.value = 0.25;
        osc.connect(comp); comp.connect(ctx.destination); osc.start(0);
        const buf = await ctx.startRendering();
        const d = buf.getChannelData(0);
        let sum = 0;
        for (let i = 4500; i < 5000; i++) sum += Math.abs(d[i]);
        return sum.toFixed(10);
      } catch (e) { return 'fel: ' + e.message; }
    },
  },
  {
    group: 'Installerat', id: 'fonts', label: 'Installerade typsnitt', bits: 12, stable: true,
    fix: 'Röjer installerad programvara: Office, Adobe, språkpaket, utvecklarverktyg. Tor exponerar bara en fast lista.',
    run: () => {
      const probes = ['monospace', 'sans-serif', 'serif'];
      const list = ['Arial', 'Arial Black', 'Calibri', 'Cambria', 'Comic Sans MS', 'Consolas',
        'Courier New', 'DejaVu Sans', 'DejaVu Serif', 'Fira Code', 'Georgia', 'Helvetica',
        'Helvetica Neue', 'Impact', 'Inter', 'JetBrains Mono', 'Liberation Sans', 'Lucida Console',
        'Menlo', 'Monaco', 'Noto Sans', 'Palatino', 'Roboto', 'SF Pro Text', 'Segoe UI',
        'Source Code Pro', 'Tahoma', 'Times New Roman', 'Trebuchet MS', 'Ubuntu', 'Verdana',
        'Cantarell', 'Nimbus Sans', 'Microsoft YaHei', 'Hiragino Sans'];
      const span = document.createElement('span');
      span.style.cssText = 'position:absolute;left:-9999px;font-size:72px';
      span.textContent = 'mmmmmmmmmmlli';
      document.body.appendChild(span);
      const base = {};
      for (const p of probes) { span.style.fontFamily = p; base[p] = [span.offsetWidth, span.offsetHeight]; }
      const found = [];
      for (const f of list) {
        for (const p of probes) {
          span.style.fontFamily = '"' + f + '",' + p;
          if (span.offsetWidth !== base[p][0] || span.offsetHeight !== base[p][1]) { found.push(f); break; }
        }
      }
      span.remove();
      return found.length + ' av ' + list.length + ' testade: ' + found.join(', ');
    },
  },
  {
    group: 'Installerat', id: 'codecs', label: 'Mediestöd (röjer OS-build och codecpaket)', bits: 5, stable: true,
    fix: 'Följer OS och installerade codecs, bl.a. om du kör en distro utan patenterade format. Svårt att maskera.',
    run: () => {
      const v = document.createElement('video'), a = document.createElement('audio');
      const t = [['video/mp4; codecs="avc1.42E01E"', v], ['video/webm; codecs="vp9"', v],
        ['video/mp4; codecs="hvc1"', v], ['video/webm; codecs="av01.0.00M.08"', v],
        ['audio/mpeg', a], ['audio/aac', a], ['audio/ogg; codecs="opus"', a], ['audio/flac', a]];
      return t.map(([m, el]) => {
        const codec = m.match(/"([^"]+)"/);
        return m.split(';')[0].split('/')[1] + (codec ? ':' + codec[1] : '') + '=' + (el.canPlayType(m) || 'no');
      }).join('  ');
    },
  },
  {
    group: 'Installerat', id: 'voices', label: 'Talsyntesröster', bits: 8, stable: true,
    fix: 'Listan speglar OS, språkpaket och installerade röstpaket. Förvånansvärt identifierande och sällan påtänkt.',
    run: () => new Promise(res => {
      if (!window.speechSynthesis) return res('ej tillgängligt');
      let done = false;
      const grab = () => {
        const v = speechSynthesis.getVoices();
        if (v.length && !done) {
          done = true;
          res(v.length + ' st: ' + v.slice(0, 8).map(x => x.name).join(', ') + (v.length > 8 ? ' …' : ''));
        }
      };
      speechSynthesis.onvoiceschanged = grab;
      grab();
      setTimeout(() => { if (!done) res('0 (eller laddades inte i tid)'); }, 700);
    }),
  },
  {
    group: 'Installerat', id: 'plugins', label: 'Plugins och PDF-visare', bits: 3, stable: true,
    fix: 'Mest en relik, men pdfViewerEnabled skiljer fortfarande webbläsare och härdade konfigurationer åt.',
    run: () => JSON.stringify({
      plugins: [...(navigator.plugins || [])].map(p => p.name),
      pdfViewerEnabled: navigator.pdfViewerEnabled,
    }),
  },
  {
    group: 'Nätverk', id: 'webrtc', label: 'WebRTC — lokala IP-adresser', bits: 6, stable: false,
    fix: 'Kan röja din LAN-adress, och utan mDNS-maskering din riktiga publika adress rakt förbi VPN-tunneln. Stäng av WebRTC eller använd en webbläsare som maskerar kandidaterna.',
    run: () => new Promise(res => {
      try {
        const pc = new RTCPeerConnection({ iceServers: [] });
        const found = new Set();
        const finish = () => { try { pc.close(); } catch (_) {} res(found.size ? [...found].join(', ') : 'inga kandidater'); };
        pc.createDataChannel('x');
        pc.onicecandidate = e => {
          if (!e.candidate) return finish();
          // SDP-format (RFC 8839), lästs per fält — inte med regex, eftersom
          // ordet "candidate:" i sig innehåller giltiga hex-tecken:
          //   candidate:<foundation> <komponent> <transport> <prio> <adress> <port> typ <typ>
          const p = e.candidate.candidate.trim().split(/\s+/);
          const addr = p[4];
          if (!addr) return;
          const ti = p.indexOf('typ');
          const kind = ti >= 0 ? p[ti + 1] : '';
          const note = addr.endsWith('.local') ? 'mDNS-maskerad'
            : kind === 'srflx' ? 'publik, via STUN'
            : kind === 'relay' ? 'via TURN-relä'
            : kind === 'host' ? 'lokal adress'
            : kind;
          found.add(addr + (note ? ' (' + note + ')' : ''));
        };
        pc.createOffer().then(o => pc.setLocalDescription(o));
        setTimeout(finish, 1500);
      } catch (e) { res('blockerad: ' + e.message); }
    }),
  },
  {
    group: 'Nätverk', id: 'netinfo', label: 'Network Information API', bits: 3, stable: false,
    fix: 'Röjer uppkopplingstyp och grov hastighet. Finns bara i Chromium-baserade webbläsare.',
    run: () => {
      const c = navigator.connection;
      if (!c) return 'stöds ej';
      return JSON.stringify({ effectiveType: c.effectiveType, downlinkMbps: c.downlink, rttMs: c.rtt, saveData: c.saveData });
    },
  },
  {
    group: 'Enhet & status', id: 'battery', label: 'Batteristatus', bits: 4, stable: false,
    fix: 'Nivå plus urladdningstid gav historiskt ett kortlivat id som kunde följa dig mellan sajter. Firefox tog bort API:et helt.',
    run: async () => {
      if (!navigator.getBattery) return 'stöds ej';
      try {
        const b = await navigator.getBattery();
        return JSON.stringify({ level: b.level, charging: b.charging, dischargingTime: b.dischargingTime });
      } catch (e) { return 'nekad'; }
    },
  },
  {
    group: 'Enhet & status', id: 'devices', label: 'Mediaenheter (antal)', bits: 4, stable: true,
    fix: 'Antalet kameror, mikrofoner och ljudutgångar syns utan att du godkänner något. Etiketterna kräver tillstånd.',
    run: async () => {
      if (!navigator.mediaDevices || !navigator.mediaDevices.enumerateDevices) return 'stöds ej';
      try {
        const d = await navigator.mediaDevices.enumerateDevices();
        const c = {};
        d.forEach(x => { c[x.kind] = (c[x.kind] || 0) + 1; });
        return JSON.stringify(c);
      } catch (e) { return 'nekad'; }
    },
  },
  {
    group: 'Enhet & status', id: 'storage', label: 'Lagringskvot (speglar diskstorlek)', bits: 5, stable: false,
    fix: 'Kvoten är normalt en andel av ledigt diskutrymme — alltså en proxy för hur stor och hur full din disk är.',
    run: async () => {
      if (!navigator.storage || !navigator.storage.estimate) return 'stöds ej';
      try {
        const e = await navigator.storage.estimate();
        return 'kvot ' + (e.quota / 1e9).toFixed(1) + ' GB, använt ' + (e.usage / 1e6).toFixed(2) + ' MB';
      } catch (e) { return '—'; }
    },
  },
  {
    group: 'Enhet & status', id: 'perms', label: 'Behörighetstillstånd', bits: 4, stable: true,
    fix: 'Mönstret av beviljade och nekade behörigheter är i sig spårbart, utan att någon enskild behörighet används.',
    run: async () => {
      if (!navigator.permissions) return 'stöds ej';
      const names = ['geolocation', 'notifications', 'camera', 'microphone', 'clipboard-read',
        'persistent-storage', 'midi', 'accelerometer'];
      const out = [];
      for (const n of names) {
        try { const s = await navigator.permissions.query({ name: n }); out.push(n + '=' + s.state); }
        catch (e) { out.push(n + '=n/a'); }
      }
      return out.join('  ');
    },
  },
  {
    group: 'Preferenser', id: 'css', label: 'CSS-mediafrågor (tillgänglighetsval)', bits: 4, stable: true,
    fix: 'Mörkt läge, reducerad rörelse och kontrastval är vanliga var för sig men delar tillsammans upp populationen fint.',
    run: () => ['prefers-color-scheme: dark', 'prefers-reduced-motion: reduce',
      'prefers-contrast: more', 'forced-colors: active', 'prefers-reduced-transparency: reduce',
      'any-pointer: coarse', 'any-hover: hover', 'dynamic-range: high']
      .map(q => q.split(':')[0].trim() + '=' + matchMedia('(' + q + ')').matches).join('  '),
  },
  {
    group: 'Preferenser', id: 'dnt', label: 'Spåra-mig-inte-signaler', bits: 2, stable: true,
    fix: 'GPC har juridisk tyngd i vissa jurisdiktioner. DNT ignoreras i praktiken och gör dig mest mer unik.',
    run: () => JSON.stringify({
      doNotTrack: navigator.doNotTrack, globalPrivacyControl: navigator.globalPrivacyControl,
      webdriver: navigator.webdriver, cookieEnabled: navigator.cookieEnabled,
    }),
  },
];

/* ------------------------------------------------------------- render -- */
function row(c, value) {
  const v = typeof value === 'string' ? value : JSON.stringify(value);
  return '<div class="row" data-id="' + c.id + '"' + tipAttrs(c.id) + '>'
    + '<div class="row-head"><span class="label">' + esc(c.label) + '</span>'
    + privBadge(c.id)
    + '<span class="bits" title="grov entropi-uppskattning">~' + c.bits + ' bits</span></div>'
    + '<div class="value">' + esc(v) + '</div>'
    + '<div class="fix"><strong>Motåtgärd:</strong> ' + esc(c.fix) + '</div></div>';
}

function serverSection(d) {
  const h = d.http, n = d.network, t = d.tls;
  const headerRows = h.headers.map(([k, v]) =>
    '<tr><td class="k">' + esc(k) + '</td><td>' + esc(v) + '</td></tr>').join('');

  let tlsHtml = '<p class="muted">Starta om med <code>python3 server.py --tls</code> för att se TLS-fingeravtrycket (JA3). '
    + 'Det följer med varje anslutning, även över VPN, och identifierar din klient oberoende av vad User-Agent påstår.</p>';
  if (t.client_hello) {
    const c = t.client_hello;
    tlsHtml = '<div class="kv"><span>JA3 MD5</span><code class="hl">' + esc(c.ja3_md5) + '</code></div>'
      + '<div class="kv"><span>TLS-version i hello</span><code>' + esc(c.client_version) + '</code></div>'
      + '<div class="kv"><span>Stödda versioner</span><code>' + esc(c.supported_versions.join(', ')) + '</code></div>'
      + '<div class="kv"><span>Chiffersviter</span><code>' + c.cipher_count + ' st, i exakt denna ordning</code></div>'
      + '<div class="kv"><span>Extensions</span><code>' + esc(c.extensions.join(' ')) + '</code></div>'
      + '<div class="kv"><span>Kurvor</span><code>' + esc(c.curves.join(' ')) + '</code></div>'
      + '<div class="kv"><span>ALPN</span><code>' + esc(c.alpn.join(', ') || '—') + '</code></div>'
      + '<div class="kv"><span>SNI (värdnamnet, i klartext)</span><code>' + esc(c.sni || '—') + '</code></div>'
      + '<div class="kv"><span>GREASE</span><code>' + (c.grease ? 'ja — Chromium-familjen' : 'nej') + '</code></div>'
      + '<pre class="raw">' + esc(c.ja3) + '</pre>'
      + '<p class="muted"><strong>Motåtgärd:</strong> Nästan ingen. Ordningen på chiffersviter och extensions bestäms av din TLS-stack, '
      + 'inte av dina inställningar. Den passerar oförändrad genom VPN och proxy, och särskiljer webbläsare, '
      + 'curl, mobilappar och automationsverktyg från varandra. Enda realistiska skyddet är att se ut som en helt vanlig webbläsare.</p>';
  }
  if (t.negotiated) {
    tlsHtml += '<div class="kv"><span>Förhandlat</span><code>' + esc(t.negotiated.version) + ' / '
      + esc(t.negotiated.cipher) + ' / ' + esc(t.negotiated.bits) + ' bitar</code></div>';
  }

  const log = d.behaviour.log.slice().reverse().map(e =>
    '<tr><td class="k">' + new Date(e.t * 1000).toLocaleTimeString() + '</td><td>' + esc(e.line)
    + '</td><td>:' + e.port + '</td></tr>').join('');

  return '<div class="row"' + tipAttrs('srv:ip') + '><div class="row-head">'
    + '<span class="label">Din IP-adress och källport</span>' + privBadge('srv:ip')
    + '<span class="bits">oundvikligt</span></div>'
    + '<div class="value">' + esc(n.ip) + ' : ' + n.source_port
    + (n.reverse_dns ? '   (reverse DNS: ' + esc(n.reverse_dns) + ')' : '') + '</div>'
    + '<div class="fix"><strong>Motåtgärd:</strong> ' + (n.is_loopback
      ? 'Du kör mot loopback, därför 127.0.0.1. Mot en riktig sajt står här din publika adress — den enda raden på hela sidan som VPN eller Tor faktiskt döljer.'
      : 'Bara VPN, Tor eller proxy döljer den här. Allt annat på sidan följer med ändå.') + '</div></div>'

    + '<div class="row"' + tipAttrs('srv:order') + '><div class="row-head">'
    + '<span class="label">Headerordning och HTTP-version</span>' + privBadge('srv:order')
    + '<span class="bits">~6 bits</span></div>'
    + '<div class="value">' + esc(h.header_order_fingerprint) + '  ·  ' + esc(h.version)
    + '  ·  ' + h.header_count + ' headers</div>'
    + '<div class="fix"><strong>Motåtgärd:</strong> Ordningen headers skickas i är klientspecifik och följer inte med när du byter '
    + 'User-Agent. Därför avslöjar en spoofad UA sig själv nästan direkt. Ingen praktisk motåtgärd utöver att använda en vanlig '
    + 'webbläsare som den är.</div></div>'

    + '<details class="sub"><summary>Råhuvud — exakt vad som gick över tråden</summary><pre class="raw">'
    + esc(h.raw_head) + '</pre></details>'
    + '<details class="sub" open><summary>Alla headers (' + h.header_count + ')</summary><table>' + headerRows + '</table></details>'
    + '<h3>TLS-handskakningen ' + privBadge('srv:tls') + '</h3>'
    + '<div class="row bare"' + tipAttrs('srv:tls') + '>' + tlsHtml + '</div>'
    + '<h3>Beteendelogg — vad servern byggt upp om dig utan att fråga</h3>'
    + '<p class="muted">Varje anrop den här sidan gjort, i ordning. Ingen cookie inblandad. '
    + 'En riktig sajt ser samma sak, plus varje länk du klickar och hur länge du dröjer.</p>'
    + '<table>' + log + '</table>';
}

/* --------------------------------------------------------------- main -- */
/* ------------------------------------------ hur lätt är du att följa -- */

/* Två axlar, inte ett betyg. Exponering är hur mycket som går att läsa;
   länkbarhet är hur väl det följer dig mellan besök. En webbläsare som
   läcker allt men slumpar värdena varje gång är svårare att följa än en
   som läcker hälften och är stabil — Brave är precis det fallet.
   Randomiseringen gissas inte: samma avläsning körs två gånger och
   jämförs. Skiljer de sig slumpar webbläsaren aktivt. */
async function detectRandomisation() {
  const out = {};
  for (const id of ['canvas', 'audio', 'webglhash']) {
    const c = COLLECTORS.find(x => x.id === id);
    if (!c) continue;
    try {
      const a = await withTimeout(c.run(), 2500, id);
      const b = await withTimeout(c.run(), 2500, id);
      out[id] = String(a) !== String(b);
    } catch (e) { out[id] = false; }
  }
  return out;
}

const LEVELS = [
  { max: 20, name: 'Svår att följa', tone: 'good',
    say: 'Din webbläsare gör aktivt motstånd. En sajt kan se en del, men inte knyta ihop det till samma person mellan besök.' },
  { max: 40, name: 'Motståndskraftig', tone: 'good',
    say: 'Mer motstånd än de flesta. Du går att följa, men det kostar ansträngning och håller inte över tid.' },
  { max: 65, name: 'Vanlig', tone: 'warn',
    say: 'Ungefär som folk är mest. Det räcker för att ett annonsnätverk ska känna igen dig mellan sajter utan en enda cookie.' },
  { max: 85, name: 'Lätt att följa', tone: 'bad',
    say: 'Du lämnar mycket ifrån dig och det är stabilt. Att känna igen dig kräver ingen ansträngning alls.' },
  { max: 101, name: 'Genomskinlig', tone: 'bad',
    say: 'Nästan allt går att läsa och ingenting ändrar sig. Du är i praktiken inloggad överallt utan att ha loggat in.' },
];

function assess(rand, distinctFps) {
  const v = window.__values || {};
  const dead = s => /^(tidsgräns|fel:|blockerad:|nekad|stöds ej|ej tillgängligt)/i.test(String(s));
  const leaks = [], shields = [];

  // Axel 1: hur stor andel av den läsbara entropin som faktiskt går att läsa.
  let readable = 0, total = 0;
  for (const c of COLLECTORS) {
    if (!c.stable) continue;
    total += c.bits;
    if (!dead(v[c.id])) readable += c.bits;
  }
  const exposure = total ? Math.round(readable / total * 100) : 0;

  // Axel 2: hur väl det följer dig. Två helt skilda mekanismer sänker den.
  // Randomisering: värdena ändrar sig, så de kan inte knytas ihop över tid.
  // Harmonisering: värdena är läsbara men delas med alla andra användare av
  // samma webbläsare. Tor gör det senare och ingenting av det förra — utan
  // den här halvan bedöms Tor som oskyddat, vilket vore rakt fel.
  let link = 100;
  let harmony = 0;
  if (rand.canvas) { link -= 30; shields.push(['Canvas randomiseras', 'Två mätningar i samma sidladdning gav olika värden. Det bryter den enskilt starkaste fingeravtryckstekniken.']); }
  else if (!dead(v.canvas)) leaks.push(['Canvas läsbar och stabil', 'Samma värde vid upprepad mätning — den duger som id rakt av.']);

  if (rand.audio) { link -= 12; shields.push(['Ljudavtrycket randomiseras', 'Ljudstackens värde ändrar sig mellan mätningar.']); }
  if (rand.webglhash) { link -= 18; shields.push(['WebGL-parametrar randomiseras', 'Drivrutinsvärdena ändrar sig mellan mätningar.']); }

  if (distinctFps > 1) {
    link -= 25;
    shields.push(['Avtrycket ändrar sig mellan besök',
      'Servern har sett ' + distinctFps + ' olika fingeravtryck från den här webbläsaren. Det är det starkaste skyddet som går att mäta här.']);
  }
  link = Math.max(0, link);

  // Övriga fynd, åt båda håll.
  const tz = String(v.tz || '');
  if (/"timeZone":"UTC"/.test(tz)) harmony++, shields.push(['Tidszonen rapporteras som UTC', 'Typiskt för Tor Browser. Döljer din geografi.']);
  else { const m = /"timeZone":"([^"]+)"/.exec(tz); if (m) leaks.push(['Tidszonen röjer var du är', m[1] + ' — följer med även bakom VPN i ett annat land.']); }

  const fm = /^(\d+) av (\d+)/.exec(String(v.fonts || ''));
  if (fm) {
    const n = Number(fm[1]);
    if (n <= 6) harmony++, shields.push(['Typsnittslistan är begränsad', 'Bara ' + n + ' exponerade — tyder på en härdad webbläsare.']);
    else if (n >= 18) leaks.push(['Många typsnitt exponerade', n + ' av ' + fm[2] + ' — röjer installerad programvara och språkpaket.']);
  }

  const gpu = /"renderer":"([^"]+)"/.exec(String(v.webgl || ''));
  if (gpu && !/swiftshader|llvmpipe|generic/i.test(gpu[1])) leaks.push(['Exakt grafikkort läsbart', gpu[1].slice(0, 70)]);
  else if (dead(v.webgl) || /ej tillgängligt/i.test(String(v.webgl))) harmony++, shields.push(['WebGL är avstängt eller dolt', 'Tar bort ett av de mest utpekande värdena.']);

  if (/stöds ej/i.test(String(v.uach))) harmony++, shields.push(['Client Hints saknas', 'Firefox och Safari lämnar inte ut dem alls.']);
  else if (!dead(v.uach)) leaks.push(['Client Hints lämnas ut', 'Exakt version, arkitektur och plattform utöver User-Agent.']);

  if (/"globalPrivacyControl":true/.test(String(v.dnt))) shields.push(['Global Privacy Control är på', 'Har juridisk tyngd i vissa jurisdiktioner, till skillnad från DNT.']);

  const cores = /"cores":(\d+)/.exec(String(v.platform || ''));
  if (cores && Number(cores[1]) <= 2) harmony++, shields.push(['Få kärnor rapporteras', 'Härdade webbläsare kapar värdet för att alla ska se lika ut.']);

  if (!dead(v.voices) && /^\d+ st/.test(String(v.voices))) leaks.push(['Talsyntesröster läsbara', 'Speglar OS, språkpaket och installerade röstpaket.']);

  // Varje harmoniseringssignal för sig är svag; flera tillsammans betyder en
  // härdad webblasare vars användare avsiktligt ser likadana ut.
  link = Math.max(0, link - Math.min(78, harmony * 16));

  const effective = Math.round(exposure * link / 100);
  const level = LEVELS.find(l => effective < l.max) || LEVELS[LEVELS.length - 1];
  return { exposure, link, effective, level, leaks, shields, readable, total,
           harmony, randomised: !!(rand.canvas || rand.audio || rand.webglhash) };
}

function meter(label, pct, tone, note) {
  return '<div class="meter"><div class="meter-head"><span>' + esc(label) + '</span>'
    + '<code>' + pct + ' %</code></div>'
    + '<div class="meter-track"><div class="meter-fill t-' + tone + '" style="width:'
    + Math.max(2, pct) + '%"></div></div>'
    + '<p class="muted">' + note + '</p></div>';
}

function renderLevel(rand, distinctFps) {
  const a = assess(rand, distinctFps);
  const expTone = a.exposure > 75 ? 'bad' : a.exposure > 45 ? 'warn' : 'good';
  const linkTone = a.link > 75 ? 'bad' : a.link > 45 ? 'warn' : 'good';

  $('#level').innerHTML =
    '<div class="levelbox t-' + a.level.tone + '">'
    + '<span class="level-label">Hur lätt du är att följa</span>'
    + '<strong class="level-name">' + esc(a.level.name) + '</strong>'
    + '<p>' + esc(a.level.say) + '</p></div>'

    + '<div class="meterpair">'
    + meter('Exponering — hur mycket som går att läsa', a.exposure, expTone,
        a.readable + ' av ' + a.total + ' bits uppskattad entropi är läsbar just nu.')
    + meter('Länkbarhet — hur väl det följer dig', a.link, linkTone,
        a.link === 100
          ? 'Varken randomisering eller harmonisering upptäckt. Allt som läses i dag läses likadant i morgon.'
          : (a.randomised ? 'Uppmätt randomisering: värdena ändrar sig, så de går inte att knyta ihop över tid. '
                          : '')
            + (a.harmony >= 2 ? 'Flera tecken på en härdad webbläsare vars användare avsiktligt ser likadana ut — '
                              + 'dina värden går att läsa, men de delas med alla andra som kör den. '
                              : '')
            + 'Det är därför du kan läcka mycket och ändå vara svår att följa.')
    + '</div>'

    + '<h3>Det här gör dig lätt att peka ut (' + a.leaks.length + ')</h3>'
    + (a.leaks.length ? '<ul class="findings bad">' + a.leaks.map(l =>
        '<li><strong>' + esc(l[0]) + '</strong><br><span class="muted">' + esc(l[1]) + '</span></li>').join('') + '</ul>'
      : '<p class="muted">Inget av det jag kan mäta. Ovanligt.</p>')

    + '<h3>Det här skyddar dig (' + a.shields.length + ')</h3>'
    + (a.shields.length ? '<ul class="findings good">' + a.shields.map(l =>
        '<li><strong>' + esc(l[0]) + '</strong><br><span class="muted">' + esc(l[1]) + '</span></li>').join('') + '</ul>'
      : '<p class="muted">Inga upptäckta skydd. Webbläsaren svarar på allt den blir tillfrågad om.</p>')

    + '<div class="verdict bad"><strong>Läs det här innan du litar på nivån.</strong> Den mäter '
    + 'bara teknisk fingeravtryckbarhet på den här maskinen. Den vet ingenting om huruvida du är '
    + 'inloggad — och är du inloggad på ett konto med ditt namn spelar ingen av siffrorna ovan '
    + 'någon roll. Den kan heller inte se hur <em>ovanligt</em> ditt värde är i världen, bara om '
    + 'det går att läsa. För uppmätt unikhet krävs en jämförelsegrupp: '
    + '<a href="#boardsection">klassrumsläget</a>. Och <a href="/skydd">guiden</a> säger vad '
    + 'som faktiskt är värt att göra åt det.</div>';
}

/* ------------------------------------------------------ navigering -- */

/* Demon och klassrumsläget ligger bakom flaggor. Utan en navigationsrad är
   de osynliga om man inte redan kan flaggorna — så raden visar dem alltid
   och säger vad som saknas när de är avstängda. */
function renderNav(f) {
  const base = location.protocol + '//';
  const port = f.port ? ':' + f.port : '';
  const items = [
    ['#s0', 'Din nivå'],
    ['#s1', 'Passivt'],
    ['#s2', 'Aktivt'],
    ['#s3', 'Utan cookies'],
    ['#s4', 'Jämför'],
    ['#s5', 'Vem du är'],
    ['#s6', 'Hur jag hittar dig'],
    ['#s7', 'Profilen'],
  ].map(([h, t]) => '<a href="' + h + '">' + t + '</a>').join('');

  // Alltid tillgangliga - de behover varken flagga eller JavaScript.
  const nojs = '<a class="ext" href="/noscript">Utan JavaScript</a>';
  const guide = '<a class="guide" href="/skydd">Skydda dig</a>';

  const demo = f.demo
    ? '<a class="ext" href="' + base + f.site_a + port + '/demo">Tredjepartsdemo</a>'
      + '<a class="ext" href="' + base + f.tracker + port + '/t/">Spårarens vy</a>'
    : '<span class="off" title="Starta om servern med --demo">Tredjepartsdemo '
      + '<code>--demo</code></span>';

  const board = f.board
    ? '<a href="#boardsection">Unik i rummet</a>'
    : '<span class="off" title="Starta om servern med --board">Unik i rummet '
      + '<code>--board</code></span>';

  $('#nav').innerHTML = items + nojs + board + demo + guide;
}

async function main() {
  // Rakt på den vanligaste missuppfattningen: privat läge byter lagringsburk,
  // inte maskin. Siffran räknas ur EXPLAIN så den aldrig hamnar ur synk.
  const ex = Object.values(EXPLAIN);
  const helps = ex.filter(e => e.priv === 'ja').length;
  const partly = ex.filter(e => e.priv === 'delvis').length;
  $('#privcount').textContent = helps + ' av ' + ex.length;
  $('#privnote').textContent = 'avläsningar på den här sidan påverkas av privat läge. '
    + partly + ' till påverkas delvis. Resten är oförändrade — hovra över en rad för att se varför.';

  const t0 = Date.now();
  const sv = await fetch('/api/server-view').then(r => r.json());
  window.__serverSkewMs = Math.round(Date.now() - sv.server_time * 1000 - (Date.now() - t0) / 2);
  $('#server').innerHTML = serverSection(sv);
  attachTips($('#server'));
  renderNav(sv.features || {});
  window.__features = sv.features || {};

  const groups = {};
  const stableParts = [];
  const values = {};
  let totalBits = 0;

  for (const c of COLLECTORS) {
    let v;
    try { v = await withTimeout(c.run(), 2500, c.id); } catch (e) { v = 'fel: ' + e.message; }
    v = ok(v);
    values[c.id] = v;
    (groups[c.group] = groups[c.group] || []).push(row(c, v));
    // Ett API som ibland svarar och ibland inte får inte ändra din identitet.
    // Misslyckade avläsningar normaliseras och bidrar inte med någon entropi.
    const failed = /^(tidsgräns|fel:|blockerad:|nekad|stöds ej|ej tillgängligt)/i.test(String(v));
    if (c.stable) {
      stableParts.push(c.id + '=' + (failed ? '[ej tillgängligt]' : v));
      totalBits += failed ? 0 : c.bits;
    }
  }
  window.__values = values;
  window.__bits = totalBits;

  $('#client').innerHTML = Object.entries(groups)
    .map(([g, rows]) => '<h3>' + esc(g) + '</h3>' + rows.join('')).join('');
  attachTips($('#client'));

  const fp = await sha256(stableParts.join('\n'));
  window.__fp = fp.slice(0, 32);
  $('#fp').textContent = fp.slice(0, 32);
  // En bit är ett ja/nej. 33 bitar (2^33 ≈ 8,6 miljarder) räcker för att ge
  // varje människa på jorden ett eget nummer — det är ankaret som gör ~111
  // begripligt i stället för abstrakt.
  const EARTH_BITS = 33;
  $('#bits').textContent = '~' + totalBits + ' bitar';
  $('#pop').innerHTML = totalBits >= EARTH_BITS
    ? 'Det räcker med <strong>33 bitar</strong> för att ge varje människa på jorden ett eget '
      + 'nummer. Du lämnar ifrån dig <strong>~' + totalBits + '</strong> — alltså långt mer än '
      + 'som behövs för att vara helt unik. <span class="muted">Grov uppskattning; attributen '
      + 'överlappar, men storleksordningen håller.</span>'
    : 'Ungefär <strong>' + totalBits + ' bitar</strong>. Det krävs 33 för att skilja alla '
      + 'människor på jorden åt, så det här räcker ännu inte för att peka ut dig ensam.';

  // Länkbarhet + automatisk sparning i samma anrop. Servern nycklar på
  // fingeravtryck + namngissning, så omladdningar slås ihop medan privat
  // läge får en egen rad.
  const attrs = {};
  for (const c of COLLECTORS) {
    attrs[c.id] = { label: c.label, v: String(values[c.id]), stable: c.stable };
  }
  const autoLabel = guessBrowser() + privateHint(values);
  const link = await fetch('/api/client-view', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      fingerprint: fp.slice(0, 32), bits: totalBits,
      label: autoLabel, attrs: attrs,
    }),
  }).then(r => r.json());
  // Mät randomisering och sätt nivån. Görs efter client-view, eftersom
  // antalet skilda avtryck servern sett är en del av bedömningen.
  detectRandomisation().then(r =>
    renderLevel(r, (link.visit && link.visit.distinct_fingerprints) || 1));

  if (link.visit) {
    window.__visitId = link.visit.id;
    $('#saved').textContent = link.visit.new
      ? 'sparat automatiskt som "' + link.visit.label + '"'
      : 'uppdaterade "' + link.visit.label + '" (' + link.visit.hits + ' besök)';
  }
  $('#link').innerHTML =
    '<div class="kv"><span>Gånger servern sett exakt detta avtryck</span><code class="hl">' + link.times_seen + '</code></div>'
    + '<div class="kv"><span>Första gången</span><code>' + new Date(link.first_seen * 1000).toLocaleString() + '</code></div>'
    + '<div class="kv"><span>Sett från IP-adresser</span><code>' + esc(link.seen_from_ips.join(', ')) + '</code></div>'
    + '<div class="kv"><span>Kända avtryck totalt</span><code>' + link.distinct_fingerprints_known + '</code></div>'
    + '<p class="muted">Ladda om sidan. Rensa gärna cookies och all lagring först. Siffran går upp ändå — '
    + 'ingenting av detta lagrades hos dig.</p>';

  // ETag-supercookie
  const px = await fetch('/api/etag-pixel', { cache: 'force-cache' });
  const known = px.headers.get('X-Leakscope-Recognised') === 'yes';
  $('#etag').innerHTML =
    '<div class="kv"><span>Igenkänd via ETag</span><code class="' + (known ? 'hl' : '') + '">'
    + (known ? 'JA' : 'nej — id utdelat nu') + '</code></div>'
    + '<div class="kv"><span>Ditt tysta id</span><code>' + esc(px.headers.get('X-Leakscope-Id') || '—') + '</code></div>'
    + '<div class="kv"><span>Träffar</span><code>' + esc(px.headers.get('X-Leakscope-Hits') || '—') + '</code></div>'
    + '<span class="privwrap"' + tipAttrs('srv:cookies') + '>' + privBadge('srv:cookies') + '</span>'
    + '<p class="muted">En helt vanlig bild med en ETag-header. Webbläsaren skickar tillbaka värdet i '
    + '<code>If-None-Match</code> vid nästa besök — ett id utan att en enda cookie sattes. Det överlever att du '
    + 'rensar cookies; bara en cache-rensning tar bort det.</p>';
  attachTips($('#etag'));

  $('#stamp').textContent = new Date().toLocaleString();

  // Jämförelsen först: den får inte bero på att namngissningen lyckas.
  await loadVisits();
  $('#label').value = autoLabel;
  loadBoard();   // tyst om servern kör utan --board
}

/* ------------------------------------------------- spara och jämför -- */

/* Gissar ett vettigt förifyllt namn. Ordningen spelar roll: Brave och Edge
   påstår sig vara Chrome, så de måste testas först. */
function guessBrowser() {
  const ua = navigator.userAgent;
  const brands = (navigator.userAgentData && navigator.userAgentData.brands || [])
    .map(b => b.brand).join(' ');
  let name = 'Okänd';
  if (navigator.brave) name = 'Brave';
  else if (/Edg\//.test(ua) || /Microsoft Edge/.test(brands)) name = 'Edge';
  else if (/OPR\//.test(ua) || /Opera/.test(brands)) name = 'Opera';
  else if (/Vivaldi/.test(ua)) name = 'Vivaldi';
  else if (/Firefox\//.test(ua)) name = /Tor/.test(ua) ? 'Tor Browser' : 'Firefox';
  else if (/Chrome\//.test(ua)) name = 'Chrome';
  else if (/Safari\//.test(ua)) name = 'Safari';
  const ver = (ua.match(/(?:Firefox|Chrome|Version)\/(\d+)/) || [])[1];
  return name + (ver ? ' ' + ver : '');
}

/* Privat läge går inte att läsa av direkt. Storage-kvoten är den bästa
   indikationen: flera webbläsare kapar den hårt i privat läge. */
/* Läser kvoten ur den redan gjorda mätningen i stället för att fråga en
   andra gång. Ett eget anrop med egen tidsgräns kunde svara olika mellan
   två laddningar, och då fick samma webbläsare två skilda namn — alltså
   två rader i listan, som om det vore två webbläsare. */
function privateHint(values) {
  const m = /kvot ([\d.]+) GB/.exec(String((values || {}).storage || ''));
  return m && parseFloat(m[1]) < 0.2 ? ' (privat?)' : '';
}

let VISITS = [];

/* Märker ut vilket sparat besök som är webbläsaren du sitter i just nu.
   Utan den går andra webbläsares värden att läsa som sina egna. */
function duMark(v) {
  return v && v.id === window.__visitId ? '<span class="dumark">du</span>' : '';
}

function visitName(v) {
  return v.label + '  ·  ' + new Date(v.t * 1000).toLocaleString();
}

async function loadVisits() {
  const d = await fetch('/api/visits').then(r => r.json()).catch(() => ({ visits: [] }));
  VISITS = d.visits || [];
  const box = $('#visits');

  if (!VISITS.length) {
    box.innerHTML = '<p class="muted">Inga sparade besök ännu. Spara det här, öppna sedan '
      + 'sidan i en annan webbläsare eller i privat läge och spara den också.</p>';
  } else {
    box.innerHTML = '<table>' + VISITS.map(v =>
      '<tr><td class="k">' + esc(v.label)
      + (v.id === window.__visitId ? ' <span class="side">det här</span>' : '') + '</td>'
      + '<td>' + new Date(v.t * 1000).toLocaleString()
      + (v.hits > 1 ? ' · ' + v.hits + ' besök' : '') + '</td>'
      + '<td><code>' + esc((v.fingerprint || '').slice(0, 16)) + '</code></td>'
      + '<td><code>' + esc(v.server && v.server.ja3_md5 ? v.server.ja3_md5.slice(0, 16) : 'ingen TLS') + '</code></td>'
      + '</tr>').join('')
      + '</table>'
      + '<p class="muted">Kolumnerna är namn, tid, fingeravtryck och JA3. '
      + (d.persisted ? 'En JSON-fil per besök i mappen <code>visits/</code>, så de överlever '
                     + 'omstart. Radera dem genom att ta bort mappen.'
                     : 'Körs med <code>--no-store</code> — finns bara i minnet.') + '</p>';
  }

  for (const sel of [$('#pickA'), $('#pickB')]) {
    const keep = sel.value;
    sel.innerHTML = VISITS.map(v => '<option value="' + esc(v.id) + '">' + esc(visitName(v)) + '</option>').join('');
    if (keep) sel.value = keep;
  }
  if (VISITS.length >= 2) {
    $('#pickA').value = VISITS[VISITS.length - 2].id;
    $('#pickB').value = VISITS[VISITS.length - 1].id;
    // Visa de två senaste direkt — det är nästan alltid den man vill se
    // efter att ha sparat i den andra webbläsaren.
    renderDiff(VISITS[VISITS.length - 2], VISITS[VISITS.length - 1]);
  } else {
    $('#diff').innerHTML = '<p class="muted">Jämförelsen kräver minst två sparade besök.</p>';
  }
  renderIdentity();
  renderNarrow(window.__invariantKeys || []);
}

/* Bygger en platt attributkarta: klientens collectors + det servern såg. */
function flatten(v) {
  const m = {};
  for (const [id, a] of Object.entries(v.attrs || {})) {
    m['c:' + id] = { label: a.label, v: a.v, stable: a.stable, side: 'klient' };
  }
  const s = v.server || {};
  const srv = [
    ['ip', 'IP-adress', s.ip, false],
    ['http_version', 'HTTP-version', s.http_version, true],
    ['header_order', 'Headerordning', (s.header_order || []).join(' → '), true],
    ['header_order_fp', 'Headerordningens avtryck', s.header_order_fp, true],
    ['ua_header', 'User-Agent (header)', (s.headers || {})['User-Agent'], true],
    ['accept', 'Accept', (s.headers || {})['Accept'], true],
    ['accept_language', 'Accept-Language', (s.headers || {})['Accept-Language'], true],
    ['accept_encoding', 'Accept-Encoding', (s.headers || {})['Accept-Encoding'], true],
    ['dnt_header', 'DNT / Sec-GPC', ((s.headers || {})['DNT'] || '') + ' ' + ((s.headers || {})['Sec-GPC'] || ''), true],
    ['ja3_md5', 'TLS JA3', s.ja3_md5, true],
    ['cipher_count', 'Antal chiffersviter', s.cipher_count, true],
    ['alpn', 'ALPN', (s.alpn || []).join(', '), true],
  ];
  for (const [id, label, val, stable] of srv) {
    m['s:' + id] = { label: label, v: val == null ? '—' : String(val), stable: stable, side: 'server' };
  }
  return m;
}

let LAST_PAIR = null;
let DIFF_ONLY = false;

/* Allt sida vid sida i EN tabell, i stället för hopfällda grupper.
   Man ska kunna läsa de två anslutningarna mot varandra rad för rad och
   se markeringarna hoppa fram där de skiljer sig. */
function renderDiff(a, b) {
  LAST_PAIR = [a, b];
  const fa = flatten(a), fb = flatten(b);
  const keys = [...new Set([...Object.keys(fa), ...Object.keys(fb)])];

  const rows = keys.map(k => {
    const x = fa[k] || { label: k, v: '—', stable: false, side: '' };
    const y = fb[k] || { label: k, v: '—', stable: false, side: '' };
    return {
      label: x.label || y.label,
      side: x.side || y.side,
      a: x.v, b: y.v,
      kind: x.v === y.v ? 'same' : (x.stable && y.stable ? 'stable' : 'volatile'),
    };
  });

  const nStable = rows.filter(r => r.kind === 'stable').length;
  const nVol = rows.filter(r => r.kind === 'volatile').length;
  const nSame = rows.filter(r => r.kind === 'same').length;
  const fpSame = a.fingerprint === b.fingerprint;

  let verdict;
  if (fpSame) {
    verdict = '<p class="verdict bad">Samma fingeravtryck. De här två anslutningarna är omöjliga '
      + 'att skilja åt för en sajt — den ser en och samma maskin, oavsett vad du rensat emellan.</p>';
  } else if (!nStable) {
    verdict = '<p class="verdict bad">Olika fingeravtryck, men inget stabilt attribut skiljer. '
      + 'Skillnaden ligger i värden som varierar även mellan två laddningar i samma webbläsare.</p>';
  } else {
    verdict = '<p class="verdict good">' + nStable + ' av ' + rows.length
      + ' attribut skiljer stabilt. Det är så mycket den ena profilen faktiskt döljer jämfört med den andra.</p>';
  }

  const marker = { stable: '◆', volatile: '◇', same: '' };
  const shown = DIFF_ONLY ? rows.filter(r => r.kind !== 'same') : rows;

  let body = '', lastSide = null;
  for (const r of shown) {
    if (r.side !== lastSide) {
      lastSide = r.side;
      body += '<tr class="grouprow"><td colspan="3">'
        + (r.side === 'server' ? 'Vad servern såg — passivt, utan JavaScript'
                               : 'Vad JavaScript kunde fråga efter') + '</td></tr>';
    }
    body += '<tr class="r-' + r.kind + '">'
      + '<td class="k"><span class="mark">' + marker[r.kind] + '</span>' + esc(r.label) + '</td>'
      + '<td>' + esc(String(r.a).slice(0, 300)) + '</td>'
      + '<td>' + esc(String(r.b).slice(0, 300)) + '</td></tr>';
  }

  $('#diff').innerHTML = verdict
    + '<div class="difflegend">'
    + '<span><b class="m-stable">◆</b> skiljer, stabilt — spårbart (' + nStable + ')</span>'
    + '<span><b class="m-vol">◇</b> skiljer, men instabilt — varierar även mellan två laddningar '
    + 'i samma webbläsare (' + nVol + ')</span>'
    + '<span><b class="m-same">·</b> identiskt (' + nSame + ')</span>'
    + '<button class="mini" id="onlydiff">' + (DIFF_ONLY ? 'Visa alla attribut' : 'Visa bara skillnader') + '</button>'
    + '</div>'
    + '<table class="difftable sidebyside">'
    + '<tr class="headrow"><td class="k">attribut</td>'
    + '<td>' + esc(a.label) + duMark(a) + '<span class="side">'
    + new Date(a.t * 1000).toLocaleString() + '</span></td>'
    + '<td>' + esc(b.label) + duMark(b) + '<span class="side">'
    + new Date(b.t * 1000).toLocaleString() + '</span></td></tr>'
    + '<tr class="r-' + (fpSame ? 'same' : 'stable') + '"><td class="k"><span class="mark">'
    + (fpSame ? '' : '◆') + '</span>Sammansatt fingeravtryck</td>'
    + '<td><code>' + esc((a.fingerprint || '').slice(0, 16)) + '</code></td>'
    + '<td><code>' + esc((b.fingerprint || '').slice(0, 16)) + '</code></td></tr>'
    + body + '</table>';

  $('#onlydiff').addEventListener('click', () => {
    DIFF_ONLY = !DIFF_ONLY;
    renderDiff(a, b);
  });
}

/* ------------------------------------------------- så här hittar jag dig -- */

/* Girig sökning: välj upprepat det attribut som skär bort flest av de
   kvarvarande kandidaterna, tills bara en är kvar. Resultatet är en
   minimal mängd som räcker för att peka ut just den webbläsaren.
   `skip` låter oss köra om utan ett visst attribut, vilket är hur
   redundansen mäts — finns en annan väg fram? */
function narrowDown(pop, target, keys, skip) {
  let cand = pop.slice();
  const chosen = [], steps = [{ label: 'Alla observerade webbläsare', n: cand.length }];
  const val = (p, k) => (p.flat[k] ? p.flat[k].v : '\u0000saknas');

  while (cand.length > 1) {
    let best = null, bestN = cand.length;
    for (const k of keys) {
      if (chosen.includes(k) || (skip && skip.includes(k))) continue;
      const n = cand.filter(p => val(p, k) === val(target, k)).length;
      if (n < bestN) { bestN = n; best = k; }
    }
    if (!best) break;                       // inget attribut skär längre
    chosen.push(best);
    cand = cand.filter(p => val(p, best) === val(target, best));
    steps.push({
      label: (target.flat[best] || {}).label || best,
      key: best,
      n: cand.length,
      value: val(target, best),
      side: (target.flat[best] || {}).side || '',
    });
  }
  return { chosen, steps, remaining: cand.length, unique: cand.length === 1 };
}

/* Översätter ett attribut till något en människa säger. Hashar visas inte —
   «ett avtryck av hur din dator ritar text» säger mer än 32 tecken hex.
   Där ett värde betyder något visas det, för det är värdena som övertygar. */
function plainPhrase(key, flat) {
  const raw = String((flat[key] || {}).v || '');
  const take = (re, i) => { const m = re.exec(raw); return m ? m[i || 1] : null; };
  const trim = (x, n) => (x && x.length > n ? x.slice(0, n) + '…' : x);

  switch (key) {
    case 'c:ua': case 's:ua_header': {
      const m = /(Firefox|Chrome|Edg|Safari|OPR)\/(\d+)/.exec(raw);
      const namn = m ? ({ Edg: 'Edge', OPR: 'Opera' }[m[1]] || m[1]) + ' ' + m[2] : 'din webbläsare';
      return 'att du använder <b>' + esc(namn) + '</b>';
    }
    case 'c:webgl': {
      const g = take(/"renderer":"([^"]+)"/);
      if (!g) return 'vilket grafikkort du har';
      // Programvarurendering säger mer om uppsättningen än något modellnamn.
      if (/swiftshader|llvmpipe|softpipe|mesa offscreen/i.test(g)) {
        return 'att du ritar grafik <b>i programvara</b> i stället för på ett grafikkort — '
          + 'ovanligt, och därför utpekande';
      }
      // Chrome paketerar namnet som ANGLE (tillverkare, modell, bakända);
      // modellen står i mitten, så att kapa vid första parentesen ger «ANGLE».
      let namn = g;
      const ang = /^ANGLE\s*\((.*)\)$/.exec(g);
      if (ang) {
        const delar = ang[1].split(', ');
        namn = delar.length > 1 ? delar[1] : delar[0];
      }
      namn = namn.replace(/\s+(Direct3D|OpenGL|Vulkan|vs_|\().*$/i, '').trim();
      return 'att ditt grafikkort är <b>' + esc(trim(namn || g, 46)) + '</b>';
    }
    case 'c:webglhash': return 'småsaker i din <b>grafikdrivrutin</b> som skiljer sig mellan datorer';
    case 'c:tz': {
      const t = take(/"timeZone":"([^"]+)"/);
      return t ? 'att din klocka står på <b>' + esc(t.split('/').pop().replace(/_/g, ' ')) + '</b>'
               : 'vilken tidszon du är i';
    }
    case 'c:screen': {
      const r = take(/"res":"([^"]+)"/);
      return r ? 'att din skärm är <b>' + esc(r) + '</b>' : 'hur stor din skärm är';
    }
    case 'c:platform': {
      const os = take(/"platform":"([^"]+)"/), k = take(/"cores":(\d+)/);
      return 'att du kör <b>' + esc(os || 'ditt system') + '</b>'
        + (k ? ' med <b>' + k + ' processorkärnor</b>' : '');
    }
    case 'c:fonts': {
      const lista = raw.split(':').slice(1).join(':').split(',').map(x => x.trim()).filter(Boolean);
      const udda = lista.find(f => /JetBrains|Fira|Source Code|Cambria|Calibri|Menlo|Ubuntu|Cantarell/i.test(f));
      const n = take(/^(\d+)/);
      return udda ? 'att du har <b>' + esc(udda) + '</b> installerat, vilket de flesta inte har'
                  : 'vilka <b>' + (n ? n + ' ' : '') + 'typsnitt</b> du har installerade';
    }
    case 'c:canvas': return 'ett avtryck av <b>hur just din dator ritar text</b> — två datorer gör det aldrig exakt lika';
    case 'c:audio': return 'ett avtryck av <b>hur din dator räknar ljud</b>';
    case 'c:voices': { const n = take(/^(\d+) st/); return 'att du har <b>' + (n || 'vissa') + ' talsyntesröster</b> installerade'; }
    case 'c:codecs': return 'vilka <b>videoformat</b> din dator kan spela upp';
    case 'c:devices': return 'hur många <b>kameror och mikrofoner</b> du har inkopplade';
    case 'c:storage': { const g = take(/kvot ([\d.]+) GB/); return g ? 'att du har ungefär <b>' + g + ' GB</b> ledigt på disken' : 'hur mycket lagring du har'; }
    case 'c:uach': return 'exakt <b>vilken version</b> av webbläsaren du kör';
    case 'c:css': return 'dina <b>visningsinställningar</b>, som mörkt läge och kontrast';
    case 'c:perms': return 'vilka <b>behörigheter</b> du tidigare svarat ja eller nej till';
    case 'c:plugins': return 'vilken <b>PDF-visare</b> din webbläsare har';
    case 'c:quirks': return 'små skillnader i <b>hur din dator räknar decimaltal</b>';
    case 'c:window': return 'hur stort ditt <b>fönster</b> är, vilket röjer dina verktygsfält';
    case 'c:netinfo': return 'vilken sorts <b>uppkoppling</b> du har';
    case 'c:battery': return 'ditt <b>batteris</b> nivå och laddningsstatus';
    case 'c:webrtc': return 'din <b>adress i det lokala nätverket</b>';
    case 'c:dnt': return 'dina <b>spåra-mig-inte-inställningar</b>';
    case 's:ip': return 'vilken <b>adress</b> du kopplar upp från';
    case 's:ja3_md5': case 's:cipher_count': case 's:alpn':
      return 'hur din dator <b>hälsar</b> när den kopplar upp — en vana den inte kan lägga av sig';
    case 's:header_order': case 's:header_order_fp':
      return '<b>ordningen</b> din webbläsare ställer sina frågor i';
    case 's:accept_language': return 'vilka <b>språk</b> du bett om';
    case 's:accept': case 's:accept_encoding': case 's:http_version':
      return 'tekniska <b>detaljer i hur din webbläsare frågar</b>';
    default: return 'något som heter <b>' + esc((flat[key] || {}).label || key) + '</b>';
  }
}

const ANTAL = ['noll', 'en', 'två', 'tre', 'fyra', 'fem', 'sex', 'sju', 'åtta', 'nio', 'tio'];
function antal(n) {
  return (n < ANTAL.length ? ANTAL[n] : String(n)) + (n === 1 ? ' sak' : ' saker');
}

function persistPhrases(chosen, invariantKeys, flat) {
  const kvar = chosen.filter(k => (invariantKeys || []).includes(k));
  if (!kvar.length) return '';
  return 'Och när du kom tillbaka i en annan webbläsare var '
    + (kvar.length === 1 ? 'en av dem fortfarande densamma — '
                         : kvar.length + ' av dem fortfarande desamma — ')
    + kvar.map(k => plainPhrase(k, flat).replace(/^att (du |din |ditt )?/, '')).join(', ')
    + '. Det är så jag vet att det är du igen, och inte någon annan.';
}

function renderNarrow(invariantKeys) {
  const box = $('#narrow');
  if (VISITS.length < 2) {
    box.innerHTML = '<p class="muted">Kräver minst två observerade webbläsare. Öppna sidan '
      + 'i en annan webbläsare — eller i privat läge — så räknar jag ut vilka attribut som '
      + 'skiljer dem åt.</p>';
    return;
  }

  const pop = VISITS.map(v => ({ id: v.id, label: v.label, flat: flatten(v) }));
  // Tidigare föll den här tillbaka på senaste besöket om uppslagningen
  // missade — och beskrev då en ANNAN webbläsares värden som om de vore
  // dina, utan att något avslöjade det. Hellre ett tydligt fel.
  const target = pop.find(p => p.id === window.__visitId);
  if (!target) {
    box.innerHTML = '<p class="verdict bad">Kunde inte avgöra vilket av de sparade besöken '
      + 'som är den här webbläsaren, så jag visar inget hellre än fel webbläsares värden. '
      + 'Ladda om sidan. Står det kvar är sparningen av det här besöket inte klar.</p>';
    return;
  }
  const keys = [...new Set(pop.flatMap(p => Object.keys(p.flat)))];

  const first = narrowDown(pop, target, keys, null);

  if (!first.unique) {
    box.innerHTML = '<p class="verdict good">Inget attribut, och ingen kombination av dem, '
      + 'skiljer den här webbläsaren från de ' + (first.remaining - 1) + ' andra. '
      + 'Du är omöjlig att peka ut i den här gruppen — så ser anonymitet faktiskt ut.</p>';
    return;
  }

  // Finns det en annan väg fram om ett av dem tas bort?
  const alt = first.chosen.map(k => ({
    key: k,
    label: (target.flat[k] || {}).label || k,
    still: narrowDown(pop, target, keys, [k]).unique,
  }));
  const removable = alt.filter(a => a.still).length;

  const maxN = first.steps[0].n;
  const funnel = first.steps.map((st, i) => {
    const pct = Math.max(3, Math.round(st.n / maxN * 100));
    return '<div class="step">'
      + '<div class="step-head"><span>' + (i === 0 ? esc(st.label)
          : '<span class="stepno">' + i + '</span> ' + esc(st.label)
            + '<span class="side">' + esc(st.side) + '</span>')
      + '</span><code>' + st.n + ' kvar</code></div>'
      + '<div class="meter-track"><div class="meter-fill t-' + (st.n === 1 ? 'bad' : 'warn')
      + '" style="width:' + pct + '%"></div></div>'
      + (i ? '<p class="muted">ditt värde: <code>' + esc(String(st.value).slice(0, 110))
             + '</code></p>' : '')
      + '</div>';
  }).join('');

  // Vilka av de utpekande attributen överlevde dina egna byten av webbläsare?
  const persist = first.chosen.filter(k => (invariantKeys || []).includes(k));

  // Klartextrutan först. Det tekniska finns kvar nedanför för den som vill,
  // men ingen ska behöva läsa en tratt för att förstå vad som pekar ut dem.
  const saker = first.chosen.map(k => plainPhrase(k, target.flat));
  const bind = persistPhrases(first.chosen, invariantKeys, target.flat);

  box.innerHTML =
    '<div class="plainbox">'
    + '<span class="plain-label">I klartext</span>'
    + '<p class="plain-lead">Den här webbläsaren — <strong>' + esc(target.label)
    + '</strong> — känner jag igen på <strong>' + antal(first.chosen.length)
    + '</strong>:</p>'
    + '<ol class="plain-list">' + saker.map(x => '<li>' + x + '</li>').join('') + '</ol>'
    + '<p class="plain-end">Det räcker. Av de <strong>' + maxN + ' webbläsare</strong> den här '
    + 'servern sett är du den enda med just den kombinationen — och jag behövde aldrig fråga '
    + 'dig om något av det. Du bara besökte sidan.</p>'
    + (removable === alt.length
        ? '<p class="plain-end">Och nej, det hjälper inte att dölja just '
          + (first.chosen.length === 1 ? 'den saken' : 'de sakerna')
          + '. Jag provade: tar jag bort '
          + (first.chosen.length === 1 ? 'den' : 'vilken som helst av dem')
          + ' hittar jag dig på nästa i stället. Det är därför enskilda knep sällan räcker.</p>'
        : '<p class="plain-end">Här finns däremot en svag punkt: '
          + (alt.length - removable) + ' av dem är jag beroende av. Döljs '
          + (alt.length - removable === 1 ? 'den' : 'de') + ' tappar jag dig faktiskt.</p>')
    + (bind ? '<p class="plain-end">' + bind + '</p>' : '')
    + '</div>'

    + '<p class="verdict bad">' + first.chosen.length + ' av ' + keys.length
    + ' attribut räcker för att peka ut just den här webbläsaren bland '
    + maxN + '. Resten behövs inte.</p>'

    + '<h3>Så här smalnar det av</h3>'
    + '<div class="funnel">' + funnel + '</div>'

    + '<h3>Går det att ta bort något?</h3>'
    + '<table class="difftable"><tr><td class="k">attribut</td>'
    + '<td>om det försvinner</td></tr>'
    + alt.map(a => '<tr class="' + (a.still ? 'r-stable' : 'r-same') + '">'
        + '<td class="k">' + esc(a.label) + '</td><td>'
        + (a.still ? 'jag hittar dig ändå, via andra attribut'
                   : 'då tappar jag dig — det här är oumbärligt')
        + '</td></tr>').join('')
    + '</table>'
    + '<p class="verdict ' + (removable === alt.length ? 'bad' : 'good') + '">'
    + (removable === alt.length
        ? 'Vart och ett av dem går att ta bort och jag hittar dig ändå. Det är därför det '
          + 'inte hjälper att blockera en enskild teknik — det finns alltid en annan väg fram.'
        : (alt.length - removable) + ' av ' + alt.length + ' är oumbärliga. Blockerar du dem '
          + 'tappar jag dig faktiskt — i den här gruppen.')
    + '</p>'

    + '<h3>Och så här vet jag att det är du igen</h3>'
    + (persist.length
        ? '<p class="verdict bad">' + persist.length + ' av de ' + first.chosen.length
          + ' attribut som pekar ut dig var <strong>identiska i varje besök</strong>, även när '
          + 'du bytte webbläsare. Det är de som binder ihop besöken till en och samma person.</p>'
          + '<ul class="findings bad">' + persist.map(k =>
              '<li><strong>' + esc((target.flat[k] || {}).label || k) + '</strong><br>'
              + '<span class="muted">' + esc(String((target.flat[k] || {}).v).slice(0, 120))
              + '</span></li>').join('') + '</ul>'
        : '<p class="verdict good">Inget av de utpekande attributen var identiskt mellan dina '
          + 'besök. Jag kan se att du är unik just nu, men inte binda ihop besöken till samma '
          + 'person.</p>')

    + '<p class="muted">Räknat mot de ' + maxN + ' webbläsare servern faktiskt observerat — '
    + 'inte mot världen. Ju fler du sparar, desto fler attribut krävs. '
    + 'Med <a href="#boardsection">klassrumsläget</a> blir gruppen riktiga besökare i stället '
    + 'för dina egna webbläsare.</p>';
}

/* ------------------------------------- vad som följer med dig överallt -- */

/* Tre hues ur standardpaletten, validerade mot sidans mörka yta för alla par
   (deutan ΔE 9.4, normalseende ΔE 20.9). Värdegruppen kodas dessutom som
   bokstav i varje cell, så identiteten vilar aldrig på färg ensam. */
const MATRIX_PAL = ['#3987e5', '#d95926', '#199e70'];
const MATRIX_REST = '#49515f';
const MAX_COLS = 8;

function bitsFor(key) {
  if (!key.startsWith('c:')) return 0;
  const c = COLLECTORS.find(x => x.id === key.slice(2));
  return c && c.stable ? c.bits : 0;
}

function renderIdentity() {
  const box = $('#identity');
  if (VISITS.length < 2) {
    box.innerHTML = '<p class="muted">Kräver minst två sparade besök. Spara det här, öppna '
      + 'sedan sidan i en annan webbläsare och spara där också.</p>';
    return;
  }

  const visits = VISITS.slice(-MAX_COLS);
  const flat = visits.map(flatten);
  const keys = [...new Set(flat.flatMap(f => Object.keys(f)))];

  const rows = keys.map(k => {
    const cells = flat.map(f => (f[k] ? f[k].v : '—'));
    const distinct = [];
    const idx = cells.map(v => {
      let i = distinct.indexOf(v);
      if (i < 0) { distinct.push(v); i = distinct.length - 1; }
      return i;
    });
    const meta = (flat.find(f => f[k]) || {})[k] || { label: k, side: '', stable: false };
    return { k, label: meta.label, side: meta.side, stable: meta.stable,
             cells, idx, n: distinct.length };
  });

  // Ett attribut som är tomt i alla besök är frånvaro av data, inte ett
  // kännetecken. Det får inte räknas som något som följer med dig.
  const blank = v => { const s = String(v == null ? '' : v).trim(); return !s || s === '—'; };
  for (const r of rows) r.empty = r.n === 1 && blank(r.cells[0]);

  const invariant = rows.filter(r => r.n === 1 && !r.empty);
  const invStable = invariant.filter(r => r.stable);
  const invVolatile = invariant.filter(r => !r.stable);
  const nEmpty = rows.filter(r => r.empty).length;
  const bits = invStable.reduce((s, r) => s + bitsFor(r.k), 0);
  // Avsnitt 6 behöver veta vilka attribut som var konstanta, för att kunna
  // säga vilka av de utpekande som dessutom binder ihop besöken.
  window.__invariantKeys = invariant.map(r => r.k);

  // Hur många genuint olika klienter tittar vi på?
  const uaRow = rows.find(r => r.k === 's:ua_header') || rows.find(r => r.k === 'c:ua');
  const clients = uaRow ? uaRow.n : 1;

  rows.sort((a, b) => (a.empty - b.empty)
    || (a.n - b.n)
    || (b.stable - a.stable)
    || bitsFor(b.k) - bitsFor(a.k)
    || a.label.localeCompare(b.label, 'sv'));

  const letter = i => String.fromCharCode(65 + i);
  const colorOf = i => (i < MATRIX_PAL.length ? MATRIX_PAL[i] : MATRIX_REST);

  const head = '<tr><td class="mk"></td>' + visits.map(v =>
    '<th scope="col"><span>' + esc(v.label) + '</span>' + duMark(v) + '</th>').join('')
    + '</tr>';

  const body = rows.map(r => {
    const cls = r.empty ? 'empty' : (r.n === 1 ? (r.stable ? 'inv' : 'inv-weak') : 'varies');
    return '<tr class="m-' + cls + '">'
      + '<td class="mk"><span class="dot"></span>' + esc(r.label)
      + '<span class="side">' + esc(r.side) + '</span></td>'
      + r.idx.map((i, j) =>
          '<td class="cell" style="background:' + colorOf(i) + '"'
          + ' data-attr="' + esc(r.label) + '" data-visit="' + esc(visits[j].label) + '"'
          + ' data-val="' + esc(String(r.cells[j]).slice(0, 300)) + '">'
          + letter(i) + '</td>').join('')
      + '</tr>';
  }).join('');

  const note = clients < 2
    ? '<p class="verdict bad">Alla sparade besök kommer från samma User-Agent. Då är nästan '
      + 'allt identiskt av trivial anledning — spara från en annan webbläsare för att det här '
      + 'ska säga något.</p>'
    : '<p class="verdict bad">' + invStable.length + ' attribut är identiska i alla '
      + visits.length + ' besök, från ' + clients + ' olika webbläsare. De '
      + invStable.filter(r => bitsFor(r.k)).length + ' av dem som har en entropi-uppskattning '
      + 'summerar till ungefär ' + bits + ' bits som följer med dig oavsett vad du byter till '
      + '— de passiva raderna tillkommer utöver det.</p>';

  box.innerHTML = note
    + '<div class="summary">'
    + '<div class="card"><span class="card-label">Följer med dig</span>'
    + '<code class="big">' + invStable.length + ' av ' + rows.length + '</code>'
    + '<span class="card-note">attribut som är identiska i varje besök</span></div>'
    + '<div class="card"><span class="card-label">Kvarvarande entropi</span>'
    + '<code class="big">~' + bits + ' bits</code>'
    + '<span class="card-note">av fingeravtryckets ~' + (window.__bits || '?')
    + ' överlever ett byte av webbläsare</span></div>'
    + '</div>'

    + '<div class="difflegend">'
    + MATRIX_PAL.map((c, i) => '<span><b class="swatch" style="background:' + c + '">'
        + letter(i) + '</b> ' + (i === 0 ? 'första värdet' : 'ett ' + (i === 1 ? 'andra' : 'tredje') + ' värde') + '</span>').join('')
    + '<span><b class="swatch" style="background:' + MATRIX_REST + '">D+</b> ytterligare värden</span>'
    + '</div>'
    + '<p class="muted">En rad med <strong>bara A</strong> betyder samma värde i varenda besök. '
    + 'Läs raderna, inte kolumnerna: de hela raderna överst är det som identifierar dig.</p>'

    + '<div class="matrixwrap"><table class="matrix">' + head + body + '</table></div>'

    + '<h3>Det här bytte du aldrig bort (' + invStable.length + ')</h3>'
    + '<ul class="invlist">' + (invStable.length
        ? invStable.map(r => '<li><strong>' + esc(r.label) + '</strong>'
            + (bitsFor(r.k) ? ' <span class="bits">~' + bitsFor(r.k) + ' bits</span>' : '')
            + '<br><code>' + esc(String(r.cells[0]).slice(0, 180)) + '</code></li>').join('')
        : '<li class="muted">Inga — ovanligt, och i så fall gott nytt.</li>') + '</ul>'
    + '<p class="muted">Dessutom ' + invVolatile.length + (invVolatile.length === 1
        ? ' attribut som är identiskt men instabilt till sin natur — det kan vara ett sammanträffande'
        : ' attribut som är identiska men instabila till sin natur — de kan vara sammanträffanden')
    + ' och räknas inte in ovan. ' + nEmpty
    + (nEmpty === 1 ? ' attribut är tomt' : ' attribut är tomma')
    + ' i samtliga besök och räknas inte alls; frånvaro av data är inget kännetecken.</p>';

  // Hovra för att se det faktiska värdet bakom varje cell.
  const tip = $('#viztip');
  box.querySelectorAll('td.cell').forEach(td => {
    td.addEventListener('mouseenter', () => {
      tip.innerHTML = '<strong>' + esc(td.dataset.attr) + '</strong><span class="t-visit">'
        + esc(td.dataset.visit) + '</span><code>' + esc(td.dataset.val) + '</code>';
      tip.setAttribute('aria-hidden', 'false');
      const r = td.getBoundingClientRect();
      tip.style.left = Math.min(r.left + scrollX, scrollX + innerWidth - 340) + 'px';
      tip.style.top = (r.bottom + scrollY + 8) + 'px';
    });
    td.addEventListener('mouseleave', () => tip.setAttribute('aria-hidden', 'true'));
  });
}

/* Sparningen sker automatiskt vid sidladdning. Det enda som finns kvar att
   göra för hand är att ge raden ett bättre namn än den gissade. */
$('#rename').addEventListener('click', async () => {
  const name = $('#label').value.trim();
  if (!name || !window.__visitId) return;
  const r = await fetch('/api/visits/label', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ id: window.__visitId, label: name }),
  }).then(r => r.json()).catch(() => null);
  $('#saved').textContent = r && r.ok ? 'omdöpt till "' + r.label + '"' : 'kunde inte döpa om';
  loadVisits();
});

$('#compare').addEventListener('click', () => {
  const a = VISITS.find(v => v.id === $('#pickA').value);
  const b = VISITS.find(v => v.id === $('#pickB').value);
  if (!a || !b) return;
  if (a.id === b.id) { $('#diff').innerHTML = '<p class="muted">Välj två olika besök.</p>'; return; }
  renderDiff(a, b);
});

/* --------------------------------------------- profilen de bygger -- */

/* Plockar isär de insamlade värdena till påståenden på vanlig svenska.
   Inget nytt mäts här — poängen är att visa vad de redan tagna värdena
   betyder tillsammans. */
function dossier() {
  const v = window.__values || {};
  const get = (k, re, i) => { const m = re.exec(String(v[k] || '')); return m ? m[i || 1] : null; };
  const claims = [];
  const add = (what, basis) => claims.push({ what, basis });

  const plat = get('platform', /"platform":"([^"]+)"/);
  const cores = get('platform', /"cores":(\d+)/);
  const mem = get('platform', /"memoryGB":(\d+)/);
  if (plat) add('Kör ' + plat + (cores ? ' med ' + cores + ' kärnor' : '')
    + (mem ? ' och minst ' + mem + ' GB RAM' : ''), 'navigator.platform, hardwareConcurrency');

  const tz = get('tz', /"timeZone":"([^"]+)"/);
  if (tz) add('Befinner sig i tidszonen ' + tz
    + (tz.includes('/') ? ' — alltså kring ' + tz.split('/')[1].replace('_', ' ') : ''),
    'Intl.DateTimeFormat');

  const langs = get('tz', /"languages":\[([^\]]+)\]/);
  if (langs) add('Talar ' + langs.replace(/"/g, ''), 'navigator.languages');

  const gpu = get('webgl', /"renderer":"([^"]+)"/);
  if (gpu) add('Har grafikkortet ' + gpu, 'WEBGL_debug_renderer_info');

  const scr = get('screen', /"res":"([^"]+)"/);
  if (scr) add('Skärm ' + scr + (/dpr":([\d.]+)/.exec(String(v.screen || ''))
    ? ' med pixeltäthet ' + /dpr":([\d.]+)/.exec(String(v.screen))[1] : ''), 'screen');

  const fonts = String(v.fonts || '');
  const dev = ['JetBrains Mono', 'Fira Code', 'Source Code Pro', 'Consolas', 'Menlo']
    .filter(f => fonts.includes(f));
  if (dev.length) add('Troligen utvecklare — har ' + dev.join(', ') + ' installerat',
    'typsnittsmätning');
  const office = ['Calibri', 'Cambria', 'Segoe UI'].filter(f => fonts.includes(f));
  if (office.length) add('Har sannolikt Microsoft Office installerat (' + office.join(', ') + ')',
    'typsnittsmätning');

  const touch = get('platform', /"touchPoints":(\d+)/);
  if (touch) add(Number(touch) > 0 ? 'Enheten har pekskärm' : 'Stationär eller bärbar utan pekskärm',
    'maxTouchPoints');

  const bat = String(v.battery || '');
  if (bat.includes('charging')) add(/"charging":true/.test(bat)
    ? 'Sitter vid ett uttag just nu' : 'Går på batteri just nu', 'Battery Status API');

  const net = get('netinfo', /"effectiveType":"([^"]+)"/);
  if (net) add('Uppkoppling av typen ' + net, 'Network Information API');

  const dark = /prefers-color-scheme=true/.test(String(v.css || ''));
  add(dark ? 'Föredrar mörkt gränssnitt' : 'Kör ljust gränssnitt', 'CSS-mediafrågor');

  const q = get('storage', /kvot ([\d.]+) GB/);
  if (q) add('Har ungefär ' + q + ' GB ledigt lagringsutrymme', 'StorageManager.estimate');

  const voices = get('voices', /^(\d+) st/);
  if (voices) add('Har ' + voices + ' talsyntesröster installerade, vilket speglar '
    + 'språkpaket och OS-version', 'speechSynthesis');

  $('#profile').innerHTML =
    '<p class="verdict bad">' + claims.length + ' påståenden, satta ihop ur sådant du '
    + 'aldrig uppgav. Ett annonsnätverk behöver inte fråga dig om något av det här.</p>'
    + '<ul class="invlist">' + claims.map(c =>
        '<li><strong>' + esc(c.what) + '</strong><br><code>källa: ' + esc(c.basis) + '</code></li>'
      ).join('') + '</ul>'
    + '<p class="muted">Lägg till besökshistoriken från avsnitt 4 och 5, och profilen följer '
    + 'dig mellan sajter. ' + (window.__features && window.__features.demo
        ? 'Det är precis den kopplingen <a href="' + location.protocol + '//'
          + window.__features.site_a + ':' + window.__features.port
          + '/demo">tredjepartsdemon</a> visar.'
        : 'Starta om med <code>--demo</code> för att se den kopplingen byggas i praktiken.')
    + '</p>';
}

$('#dossier').addEventListener('click', dossier);

/* ------------------------------------------------- klassrumsläget -- */

async function loadBoard() {
  if (!window.__fp) return;
  const d = await fetch('/api/board', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ fingerprint: window.__fp, attrs: window.__values || {} }),
  }).then(r => r.json()).catch(() => null);

  if (!d || d.off) {
    $('#board').innerHTML = '<p class="muted">Avstängt. Starta om servern med '
      + '<code>--board</code> så mäts unikheten över alla som surfar in — '
      + 'kör <code>--host 0.0.0.0 --board</code> om du vill släppa in ett helt rum. '
      + 'Läget samlar uppgifter om andra än dig, därför är det avstängt som standard.</p>';
    return;
  }

  const rows = d.rows.filter(r => r.my_value != null);
  const comparable = rows.filter(r => r.enough_data);
  const uniqueHere = comparable.filter(r => r.unique_here).length;

  $('#board').innerHTML =
    '<p class="verdict ' + (d.you_are_unique ? 'bad' : 'good') + '">'
    + (d.fingerprints < 2
        ? 'Än så länge är du ensam besökare. Be fler att surfa in, så blir siffrorna meningsfulla.'
        : d.you_are_unique
          ? 'Ditt avtryck delas inte av någon annan av de ' + d.devices
            + ' enheter som varit här. Du är unikt identifierbar i den här gruppen.'
          : 'Ditt avtryck delas med ' + d.you_share_with_devices + ' annan enhet här. '
            + 'Det är ovanligt — och det är så anonymitet faktiskt ser ut: att vara en av flera.')
    + '</p>'
    + '<div class="summary">'
    + '<div class="card"><span class="card-label">Enheter</span><code class="big">'
    + d.devices + '</code><span class="card-note">skilda IP-adresser har surfat in</span></div>'
    + '<div class="card"><span class="card-label">Unika avtryck</span><code class="big">'
    + d.unique_fingerprints + ' av ' + d.fingerprints
    + '</code><span class="card-note">avtryck som ingen annan enhet delar</span></div>'
    + '<div class="card"><span class="card-label">Pekar ut dig ensam</span><code class="big">'
    + uniqueHere + ' av ' + comparable.length
    + '</code><span class="card-note">attribut där ditt värde är unikt bland dem som går '
    + 'att jämföra</span></div>'
    + '</div>'
    + '<h3>Hur sällsynt är varje värde — mätt här, inte uppskattat</h3>'
    + '<table class="difftable"><tr><td class="k">attribut</td><td>delar värdet med</td>'
    + '<td>olika värden i gruppen</td></tr>'
    + rows.map(r => '<tr class="' + (r.unique_here ? 'r-stable'
          : r.enough_data ? 'r-same' : 'r-empty') + '">'
        + '<td class="k">' + esc(r.key) + '</td>'
        + '<td>' + (!r.enough_data ? 'för få mätvärden'
            : r.you_share_with <= 1 ? 'ingen annan'
            : (r.you_share_with - 1) + ' av ' + (r.coverage - 1)) + '</td>'
        + '<td>' + r.distinct + '</td></tr>').join('')
    + '</table>'
    + '<p class="muted">Raden "ingen annan" betyder att just ditt värde är unikt bland '
    + 'besökarna här. Ju fler sådana rader, desto lättare är du att peka ut. '
    + '"För få mätvärden" betyder att bara du rapporterat något för den raden — '
    + 'det bevisar ingen unikhet, det saknas bara jämförelsematerial.</p>';
}

$('#reload').addEventListener('click', () => location.reload());

main();
