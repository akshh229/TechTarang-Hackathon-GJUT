/* ===== SOFT AURORA — WebGL Background ===== */
(function () {
  const canvas = document.getElementById('aurora-canvas');
  if (!canvas) return;
  const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
  if (!gl) return;

  /* --- Config matching SoftAurora props --- */
  const CFG = {
    speed: 0.6,
    scale: 1.5,
    brightness: 1.0,
    color1: [0.969, 0.969, 0.969],   // #f7f7f7
    color2: [0.882, 0.0, 1.0],       // #e100ff
    noiseFreq: 2.5,
    noiseAmp: 1.0,
    bandHeight: 0.5,
    bandSpread: 1.1,
    octaveDecay: 0.1,
    colorSpeed: 1.0,
    mouseInfluence: 0.45,
  };

  let mouseX = 0.5, mouseY = 0.5;
  let smoothMouseX = 0.5, smoothMouseY = 0.5;

  document.addEventListener('mousemove', (e) => {
    mouseX = e.clientX / window.innerWidth;
    mouseY = 1.0 - e.clientY / window.innerHeight;
  });

  /* --- Shaders --- */
  const VERT = `
    attribute vec2 a_pos;
    void main() { gl_Position = vec4(a_pos, 0.0, 1.0); }
  `;

  const FRAG = `
    precision highp float;
    uniform float u_time;
    uniform vec2  u_res;
    uniform vec2  u_mouse;
    uniform float u_speed;
    uniform float u_scale;
    uniform float u_brightness;
    uniform vec3  u_color1;
    uniform vec3  u_color2;
    uniform float u_noiseFreq;
    uniform float u_noiseAmp;
    uniform float u_bandHeight;
    uniform float u_bandSpread;
    uniform float u_octaveDecay;
    uniform float u_colorSpeed;
    uniform float u_mouseInf;

    /* --- Simplex 2D noise (Ashima Arts) --- */
    vec3 mod289(vec3 x) { return x - floor(x * (1.0/289.0)) * 289.0; }
    vec2 mod289v2(vec2 x) { return x - floor(x * (1.0/289.0)) * 289.0; }
    vec3 permute(vec3 x) { return mod289(((x*34.0)+1.0)*x); }

    float snoise(vec2 v) {
      const vec4 C = vec4(0.211324865405187, 0.366025403784439,
                         -0.577350269189626, 0.024390243902439);
      vec2 i  = floor(v + dot(v, C.yy));
      vec2 x0 = v - i + dot(i, C.xx);
      vec2 i1 = (x0.x > x0.y) ? vec2(1.0,0.0) : vec2(0.0,1.0);
      vec4 x12 = x0.xyxy + C.xxzz;
      x12.xy -= i1;
      i = mod289v2(i);
      vec3 p = permute(permute(i.y + vec3(0.0,i1.y,1.0)) + i.x + vec3(0.0,i1.x,1.0));
      vec3 m = max(0.5 - vec3(dot(x0,x0), dot(x12.xy,x12.xy), dot(x12.zw,x12.zw)), 0.0);
      m = m*m; m = m*m;
      vec3 x_ = 2.0*fract(p * C.www) - 1.0;
      vec3 h = abs(x_) - 0.5;
      vec3 ox = floor(x_ + 0.5);
      vec3 a0 = x_ - ox;
      m *= 1.79284291400159 - 0.85373472095314*(a0*a0+h*h);
      vec3 g;
      g.x = a0.x*x0.x + h.x*x0.y;
      g.yz = a0.yz*x12.xz + h.yz*x12.yw;
      return 130.0 * dot(m, g);
    }

    float fbm(vec2 p, float t) {
      float v = 0.0;
      float a = 1.0;
      for (int i = 0; i < 4; i++) {
        v += a * snoise(p + t * 0.15);
        p *= 2.0;
        a *= u_octaveDecay + 0.4;
      }
      return v;
    }

    void main() {
      vec2 uv = gl_FragCoord.xy / u_res;
      float aspect = u_res.x / u_res.y;
      vec2 p = (uv - 0.5) * vec2(aspect, 1.0) * u_scale;

      float t = u_time * u_speed;

      /* Mouse displacement */
      vec2 mOff = (u_mouse - 0.5) * u_mouseInf;
      p += mOff;

      /* Noise layers */
      float n1 = fbm(p * u_noiseFreq, t);
      float n2 = fbm(p * u_noiseFreq * 0.7 + 5.0, t * 0.8);

      /* Aurora band shape — horizontal band with noise displacement */
      float yOff = n1 * u_noiseAmp * 0.25;
      float band = exp(-pow((p.y - yOff) / (u_bandSpread * 0.35), 2.0) / (u_bandHeight * 0.5));
      float band2 = exp(-pow((p.y - n2 * u_noiseAmp * 0.15 + 0.1) / (u_bandSpread * 0.25), 2.0) / (u_bandHeight * 0.3));

      /* Color mixing — shift across x and over time */
      float colorMix = uv.x + n1 * 0.2 + sin(t * u_colorSpeed * 0.3) * 0.15;
      colorMix = clamp(colorMix, 0.0, 1.0);
      vec3 col = mix(u_color1, u_color2, colorMix);

      /* Secondary color for depth */
      vec3 col2 = mix(u_color2, u_color1 * 0.6, clamp(1.0 - colorMix + 0.3, 0.0, 1.0));

      /* Combine bands */
      vec3 aurora = col * band * 0.8 + col2 * band2 * 0.35;
      aurora *= u_brightness;

      /* Soft vignette */
      float vig = 1.0 - 0.3 * length((uv - 0.5) * vec2(1.0, 1.5));

      /* Final composite on dark background */
      vec3 bg = vec3(0.02, 0.02, 0.03);
      vec3 final_color = bg + aurora * vig;

      /* Subtle glow bloom */
      float glow = (band + band2 * 0.5) * 0.08;
      final_color += col * glow * vig;

      gl_FragColor = vec4(final_color, 1.0);
    }
  `;

  /* --- Compile shader --- */
  function compile(src, type) {
    const s = gl.createShader(type);
    gl.shaderSource(s, src);
    gl.compileShader(s);
    if (!gl.getShaderParameter(s, gl.COMPILE_STATUS)) {
      console.error('Shader error:', gl.getShaderInfoLog(s));
      return null;
    }
    return s;
  }

  const vs = compile(VERT, gl.VERTEX_SHADER);
  const fs = compile(FRAG, gl.FRAGMENT_SHADER);
  if (!vs || !fs) return;

  const prog = gl.createProgram();
  gl.attachShader(prog, vs);
  gl.attachShader(prog, fs);
  gl.linkProgram(prog);
  if (!gl.getProgramParameter(prog, gl.LINK_STATUS)) {
    console.error('Link error:', gl.getProgramInfoLog(prog));
    return;
  }
  gl.useProgram(prog);

  /* --- Full-screen quad --- */
  const buf = gl.createBuffer();
  gl.bindBuffer(gl.ARRAY_BUFFER, buf);
  gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1,-1, 1,-1, -1,1, 1,1]), gl.STATIC_DRAW);
  const aPos = gl.getAttribLocation(prog, 'a_pos');
  gl.enableVertexAttribArray(aPos);
  gl.vertexAttribPointer(aPos, 2, gl.FLOAT, false, 0, 0);

  /* --- Uniforms --- */
  const loc = {};
  ['u_time','u_res','u_mouse','u_speed','u_scale','u_brightness',
   'u_color1','u_color2','u_noiseFreq','u_noiseAmp','u_bandHeight',
   'u_bandSpread','u_octaveDecay','u_colorSpeed','u_mouseInf'
  ].forEach(n => loc[n] = gl.getUniformLocation(prog, n));

  /* Set static uniforms */
  gl.uniform1f(loc.u_speed, CFG.speed);
  gl.uniform1f(loc.u_scale, CFG.scale);
  gl.uniform1f(loc.u_brightness, CFG.brightness);
  gl.uniform3fv(loc.u_color1, CFG.color1);
  gl.uniform3fv(loc.u_color2, CFG.color2);
  gl.uniform1f(loc.u_noiseFreq, CFG.noiseFreq);
  gl.uniform1f(loc.u_noiseAmp, CFG.noiseAmp);
  gl.uniform1f(loc.u_bandHeight, CFG.bandHeight);
  gl.uniform1f(loc.u_bandSpread, CFG.bandSpread);
  gl.uniform1f(loc.u_octaveDecay, CFG.octaveDecay);
  gl.uniform1f(loc.u_colorSpeed, CFG.colorSpeed);
  gl.uniform1f(loc.u_mouseInf, CFG.mouseInfluence);

  /* --- Resize --- */
  function resize() {
    const dpr = Math.min(window.devicePixelRatio, 1.5); // cap for perf
    canvas.width = window.innerWidth * dpr;
    canvas.height = window.innerHeight * dpr;
    canvas.style.width = window.innerWidth + 'px';
    canvas.style.height = window.innerHeight + 'px';
    gl.viewport(0, 0, canvas.width, canvas.height);
  }
  window.addEventListener('resize', resize);
  resize();

  /* --- Render loop --- */
  const start = performance.now();
  function frame() {
    const t = (performance.now() - start) / 1000;

    /* Smooth mouse */
    smoothMouseX += (mouseX - smoothMouseX) * 0.05;
    smoothMouseY += (mouseY - smoothMouseY) * 0.05;

    gl.uniform1f(loc.u_time, t);
    gl.uniform2f(loc.u_res, canvas.width, canvas.height);
    gl.uniform2f(loc.u_mouse, smoothMouseX, smoothMouseY);

    gl.drawArrays(gl.TRIANGLE_STRIP, 0, 4);
    requestAnimationFrame(frame);
  }
  frame();
})();
