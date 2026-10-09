(() => {
  const pairs = [
    ['Console', '콘솔'], ['Run source (F5)', '원본 실행 (F5)'], ['Run output (Shift+F5)', '결과 실행 (Shift+F5)'],
    ['Stop execution', '실행 중지'], ['Clear console', '콘솔 지우기'], ['Hide console', '콘솔 접기'],
    ['Execution console', '실행 콘솔'], ['Execution output', '실행 출력'], ['Execution input', '실행 입력'],
    ['Send input', '입력 보내기'], ['Type and press Enter', '입력 후 Enter'],
    ['Starting…', '시작 중…'], ['Running', '실행 중'], ['Finished', '종료'], ['Stopped', '중지됨'], ['Run failed', '실행 실패'],
    ['Earlier output omitted', '이전 출력 생략됨'], ['No code to run', '실행할 코드 없음'],
    ['Runner closed', '실행기 종료됨'], ['Code is already running', '이미 실행 중입니다'],
    ['Code is not running', '실행 중인 코드 없음'], ['Execution no longer available', '실행 기록 없음'],
    ['Input queue full', '입력 대기열이 가득합니다'], ['Input is too long (4096 characters maximum)', '입력은 최대 4096자입니다'],
    ['Preferences', '환경설정'], ['Theme', '테마'], ['Editor', '편집기'], ['General', '일반'],
    ['Language', '언어'], ['Build settings', '빌드 설정'], ['Settings', '설정'], ['Source', '코드'], ['Output', '결과'],
    ['Open', '열기'], ['Clear', '지우기'], ['Copy', '복사'], ['Save', '저장'], ['Obfuscate', '난독화'],
    ['Save configuration', '설정 저장'], ['GUI preferences', '환경설정'], ['Close', '닫기'],
    ['Fast', '빠르게'], ['Balanced', '균형'], ['Strong', '강하게'], ['Maximum', '최대'], ['Custom settings', '커스텀 설정'],
    ['＋ Marker', '＋ 마커'], ['Selective protection', '선택 보호'], ['Always applied', '항상 적용'],
    ['Type', '종류'], ['Options', '옵션'], ['Insert', '삽입'], ['String', '문자열'], ['Number', '숫자'],
    ['Boolean', '불리언'], ['Table', '테이블'], ['Function', '함수'], ['VM region', 'VM 영역'],
    ['Function region', '함수 내부 영역'], ['Whole-file VM', '파일 전체 VM'], ['Exclude function from VM', '함수 VM 제외'],
    ['Exclude region from VM', '영역 VM 제외'], ['Exclude region from protection', '영역 보호 제외'],
    ['Select a string literal → insert', '문자열 리터럴 선택 → 삽입'], ['Select a number literal → insert', '숫자 리터럴 선택 → 삽입'],
    ['Select true / false → insert', 'true / false 선택 → 삽입'], ['Select a table { … } → insert', '테이블 { … } 선택 → 삽입'],
    ['Select complete statements → VM region', '완전한 문장들을 선택 → VM 영역'], ['Insert before a function', '함수 앞에 삽입'],
    ['Select statements inside a function → protect', '함수 내부 문장들을 선택 → 보호 영역'], ['Insert at the start of the file', '파일 맨 앞에 삽입'],
    ['Insert before a function → exclude VM', '함수 앞에 삽입 → VM 제외'], ['Select statements → exclude VM', '문장들을 선택 → VM 제외'],
    ['Select statements → exclude protection', '문장들을 선택 → 보호 제외'],
    ['Select code in the editor first.', '코드에서 보호할 부분을 먼저 선택하세요.'], ['Keep options on a single line.', '옵션은 한 줄로 입력하세요.'],
    ['Marker inserted', '마커 삽입됨'], ['Density', '간격'], ['Comfortable', '여유롭게'], ['Compact', '좁게'],
    ['Remember sections', '설정 그룹 상태 기억'], ['Font size', '글자 크기'], ['Motion', '애니메이션'],
    ['System', '시스템'], ['Reduced', '줄이기'], ['Full', '전체'], ['Changes save automatically', '자동 저장'],
    ['Saved automatically', '저장됨'], ['Saving…', '저장 중…'], ['Reset defaults', '초기화'],
    ['Ready', '준비'], ['Source loaded', '코드 불러옴'], ['Input required', '코드를 입력하세요'],
    ['Protecting…', '난독화 중…'], ['Protection complete', '완료'], ['Protection complete (options ignored)', '완료 · 경고 확인'],
    ['Build failed', '실패'], ['Copied', '복사됨'], ['Output saved', '저장됨'], ['Nothing to save', '저장할 결과 없음'],
    ['Opening file…', '파일 여는 중…'], ['Open failed', '파일 열기 실패'], ['Copy failed', '복사 실패'],
    ['Save cancelled', '저장 취소됨'], ['Initialization failed', '초기화 실패'], ['Saved locally', '설정 저장됨'], ['Save failed', '저장 실패'],
    ['Release check', '배포 검사'], ['Advanced settings', '고급 설정'], ['Preset', '프리셋'], ['Protect level', '보호 강도'],
    ['Light', '가볍게'], ['Pipeline', '파이프라인'], ['Source & main', '원본 처리'], ['VM output', 'VM 출력'], ['Packer output', '패커 출력'],
    ['Lua toolchain', 'Lua 도구'], ['Lua version', 'Lua 버전'], ['Environment', '환경'], ['Compatibility', '호환성'],
    ['Standalone', '독립 실행'], ['Portable', '이식성 우선'], ['Runtime specific', '런타임 전용'], ['Binary specific', '바이너리 전용'],
    ['Lua executable', 'Lua 실행 파일'], ['Luac executable', 'Luac 실행 파일'], ['Lua library (overrides executables)', 'Lua 라이브러리'],
    ['Signature', '서명'], ['Mode', '방식'], ['Default', '기본'], ['None', '없음'], ['Fake signature', '가짜 서명'],
    ['Candidate sources', '후보'], ['Well-known samples', '알려진 샘플'], ['Use generator', '생성기'], ['Generator patterns', '생성 패턴'],
    ['Custom pattern', '커스텀 패턴'], ['Custom', '커스텀'], ['Comment text', '주석 내용'],
    ['Execution', '실행'], ['Handlers', '핸들러'], ['Integrity', '무결성'], ['Semantic routing', '의미 라우팅'],
    ['Runtime diversity', '런타임 다양성'], ['Choke-point diversity', '핵심 경로 다양성'], ['Advanced', '고급'],
    ['Strip Info', '정보 제거'], ['Remove Comment', '주석 제거'], ['Encode String', '문자열 인코딩'],
    ['String Obfuscation', '문자열 난독화'], ['Boolean Obfuscation', '불리언 난독화'], ['Number Obfuscation', '숫자 난독화'],
    ['Table Obfuscation', '테이블 난독화'], ['Function Obfuscation', '함수 난독화'], ['Rename Obfuscation', '이름 난독화'],
    ['Localize Globals', '전역 지역화'], ['Minify', '압축'], ['Meme / Fun Strings', '밈 문자열'],
    ['VM runtime', 'VM 런타임'], ['Dispatcher', '디스패처'], ['Blob representation', '블롭 형식'], ['VM count', 'VM 수'],
    ['Fake handlers', '가짜 핸들러'], ['Handler mutation', '핸들러 변형'], ['Junk instructions', '정크 명령'], ['Junk rate', '정크 비율'],
    ['Integrity constants', '무결성 상수'], ['Integrity constant rate', '무결성 상수 비율'], ['Graph execution rate', '그래프 실행 비율'],
    ['Cross-instruction rate', '명령 간 연계 비율'], ['Runtime polymorphism rate', '런타임 다형성 비율'],
    ['Runtime trace diagnostics', '런타임 추적'], ['Block variant rate', '블록 변형 비율'], ['Block variants', '블록 변형 수'],
    ['Block size limit', '블록 크기 제한'], ['Helper variants', '헬퍼 변형 수'], ['Helper diversity rate', '헬퍼 다양성 비율'],
    ['Semantic diversity rate', '의미 다양성 비율'], ['Optional', '선택'], ['Required', '필수'],
    ['Paste Lua code or open a file.', 'Lua 코드를 붙여넣거나 파일을 여세요.'], ['Protected output appears here.', '난독화 결과가 여기에 표시됩니다.'],
    ['Split view', '나란히 보기'], ['Code view', '코드 보기'], ['Workspace', '작업 화면'], ['GUI design', 'GUI 디자인'],
    ['Minimize', '최소화'], ['Maximize', '최대화'], ['Choose a preset or tune individual controls.', '프리셋을 고르거나 설정을 조정하세요.'],
    ['Input cleared.', '입력을 지웠습니다.'], ['Run protection first.', '먼저 난독화를 실행하세요.'], ['Protected output copied to clipboard.', '결과를 복사했습니다.'],
    ['Waiting for file selection.', '파일 선택 대기 중입니다.'], ['File selection cancelled.', '파일 선택을 취소했습니다.'],
    ['Paste Lua source or open a file.', 'Lua 코드를 붙여넣거나 파일을 여세요.'],
    ['Requirements', '필수 보호 기능'], ['Dispatcher Target Hiding', '디스패처 대상 숨김'], ['Semantic State Threading', '의미 상태 연계'],
    ['Argument Virtualization', '인자 가상화'], ['Upvalue Virtualization', '업밸류 가상화'], ['Table Virtualization', '테이블 가상화'], ['Branch Virtualization', '분기 가상화'],
    ['Anti-Debug Wrapper', '안티 디버그'], ['Anti-Decompile (unluac trap)', '안티 디컴파일'], ['Packer (deflate + load)', '패커'],
    ['Protection setup', '보호 설정'], ['BUILD CONFIGURATION', '빌드 구성'], ['ACTIVE BUILD', '현재 빌드'],
    ['Execution pipeline', '실행 순서'], ['No passes selected', '선택된 패스 없음'], ['Select at least one main pass', '패스를 하나 이상 선택하세요'],
    ['GUI Preferences', 'GUI 환경설정'], ['Insert protection markers around selected code', '선택한 코드에 보호 마커 삽입'],
    ['Close preferences', '환경설정 닫기'], ['Release security validation', '배포용 보안 설정 검사'],
    ['Custom marker options', '커스텀 마커 옵션'], ['Lua source', 'Lua 원본'], ['Lua output', 'Lua 결과'],
    ['Lua 5.1 (experimental)', 'Lua 5.1 (실험적)'], ['Host images (one executable or DLL path per line)', '호스트 이미지 (한 줄에 파일 하나)'],
    ['Start with a preset and adjust what you need.', '프리셋으로 시작하고 필요한 항목만 직접 조정하세요.'],
    ['VM and packer need Runtime specific or higher. Lua 5.1 supports explicit tools or a library, with Lupa as the default. Some source passes remain unavailable. CE selection declares host capabilities; it does not enable native protection by itself.', 'VM·패커는 런타임 전용 이상의 호환성이 필요합니다. Lua 5.1은 Lupa를 기본으로 사용하며 실행 파일·라이브러리를 지정할 수도 있습니다. 일부 원본 패스는 지원되지 않습니다. CE 선택은 호스트 기능만 선언하며 네이티브 보호를 켜지 않습니다.'],
    ['For either Lua version, a matching library takes priority for compilation and integrity dumps. Leave empty to use executables.', '컴파일과 무결성 덤프는 지정한 Lua 라이브러리를 우선 사용합니다. 비우면 실행 파일을 사용합니다.'],
  ];
  const lookup = new Map();
  for (const pair of pairs) for (const text of pair) lookup.set(text, pair);
  const originals = new WeakMap();
  const attributes = new WeakMap();
  const tr = (text, language) => lookup.get(text)?.[language === 'en' ? 0 : 1] || text;
  function localize(root, language) {
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
    while (walker.nextNode()) {
      const node = walker.currentNode;
      if (node.parentElement.closest('script, style, textarea, pre, code, .filename, #config-source, #profile-summary, #status-msg, #preferences-status, #quick-preset-status, #execution-status, .theme-tile')) continue;
      if (!originals.has(node)) originals.set(node, node.nodeValue);
      const original = originals.get(node), trimmed = original.trim();
      if (trimmed) node.nodeValue = original.replace(trimmed, tr(trimmed, language));
    }
    root.querySelectorAll('[title], [aria-label]').forEach(element => {
      if (!attributes.has(element)) attributes.set(element, {title: element.title, label: element.getAttribute('aria-label')});
      const original = attributes.get(element);
      if (original.title) element.title = tr(original.title, language);
      if (original.label) element.setAttribute('aria-label', tr(original.label, language));
    });
  }
  window.GuiI18n = {tr, localize};
})();
