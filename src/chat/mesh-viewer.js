/**
 * @file src/chat/mesh-viewer.js
 * @description Visor 3D interactivo en navegador para archivos de malla (.obj, .stl, .glb, .gltf).
 * Permite inspeccionar geometría, alternar modos de sombreado (Arcilla / Wireframe / Sólido + Malla),
 * y calcular estadísticas de topología (vértices, triángulos, quads y n-gons).
 */

/**
 * Extensiones 3D compatibles con el visor interactivo.
 */
const SUPPORTED_3D_EXTENSIONS = /\.(obj|stl|gltf|glb)$/i;

/**
 * Determina si un nombre de archivo corresponde a un modelo 3D inspeccionable.
 * @param {string} fileName
 * @returns {boolean}
 */
export function isInspectable3D(fileName) {
  if (typeof fileName !== 'string') return false;
  return SUPPORTED_3D_EXTENSIONS.test(fileName.trim());
}

/**
 * Devuelve el formato normalizado del archivo 3D o null si no está soportado.
 * @param {string} fileName
 * @returns {'obj'|'stl'|'gltf'|'glb'|null}
 */
export function get3DFormat(fileName) {
  if (typeof fileName !== 'string') return null;
  const match = fileName.trim().match(SUPPORTED_3D_EXTENSIONS);
  return match ? match[1].toLowerCase() : null;
}

/**
 * Analiza el contenido textual de un archivo Wavefront OBJ y calcula estadísticas de topología.
 * @param {string} objText
 * @returns {{ vertices: number, normals: number, uvs: number, faces: number, triangles: number, quads: number, ngons: number, hasNormals: boolean, hasUvs: boolean }}
 */
export function parseObjStats(objText) {
  if (typeof objText !== 'string') {
    return { vertices: 0, normals: 0, uvs: 0, faces: 0, triangles: 0, quads: 0, ngons: 0, hasNormals: false, hasUvs: false };
  }

  let vertices = 0;
  let normals = 0;
  let uvs = 0;
  let faces = 0;
  let triangles = 0;
  let quads = 0;
  let ngons = 0;

  const lines = objText.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (line.length < 2 || line.charCodeAt(0) === 35) continue; // Ignorar comentarios (#)

    if (line.startsWith('v ')) {
      vertices++;
    } else if (line.startsWith('vn ')) {
      normals++;
    } else if (line.startsWith('vt ')) {
      uvs++;
    } else if (line.startsWith('f ')) {
      faces++;
      const tokens = line.slice(2).trim().split(/\s+/);
      const vertCount = tokens.length;
      if (vertCount === 3) {
        triangles += 1;
      } else if (vertCount === 4) {
        quads += 1;
        triangles += 2;
      } else if (vertCount > 4) {
        ngons += 1;
        triangles += (vertCount - 2);
      }
    }
  }

  return {
    vertices,
    normals,
    uvs,
    faces,
    triangles,
    quads,
    ngons,
    hasNormals: normals > 0,
    hasUvs: uvs > 0
  };
}

/**
 * Analiza un búfer binario o ASCII de STL y calcula el conteo de facetas y vértices.
 * @param {ArrayBuffer|Uint8Array} buffer
 * @returns {{ triangles: number, vertices: number, isBinary: boolean }}
 */
export function parseStlStats(buffer) {
  if (!buffer) {
    return { triangles: 0, vertices: 0, isBinary: false };
  }

  const byteLength = buffer.byteLength || buffer.length || 0;
  if (byteLength < 84) {
    return { triangles: 0, vertices: 0, isBinary: false };
  }

  const uint8 = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  const view = new DataView(uint8.buffer, uint8.byteOffset, byteLength);
  const triCount = view.getUint32(80, true);

  if (byteLength === 84 + (triCount * 50)) {
    return {
      triangles: triCount,
      vertices: triCount * 3,
      isBinary: true
    };
  }

  // Fallback: conteo ASCII
  try {
    const text = new TextDecoder('utf-8').decode(uint8.subarray(0, Math.min(byteLength, 100000)));
    const matches = text.match(/facet\s+normal/gi);
    const count = matches ? matches.length : 0;
    return {
      triangles: count,
      vertices: count * 3,
      isBinary: false
    };
  } catch {
    return { triangles: 0, vertices: 0, isBinary: false };
  }
}

/**
 * Formatea las estadísticas de topología para su visualización en la interfaz.
 * @param {Object} stats
 * @returns {string}
 */
export function formatPolycount(stats) {
  if (!stats) return '';
  const numFmt = new Intl.NumberFormat('es-ES');
  const vStr = numFmt.format(stats.vertices || 0);
  const tStr = numFmt.format(stats.triangles || 0);

  if (typeof stats.quads === 'number' && stats.quads > 0) {
    const qStr = numFmt.format(stats.quads);
    return `V: ${vStr} | Tris: ${tStr} | Quads: ${qStr}`;
  }
  return `Vértices: ${vStr} | Triángulos: ${tStr}`;
}

// --- Estado global del visor activo ---
let activeSceneState = null;

/**
 * Abre el modal de inspección 3D y carga la geometría.
 * @param {string} fileUrl - URL Blob o accesible del archivo
 * @param {string} fileName - Nombre del archivo (ej. modelo.obj)
 */
export async function openMeshViewerModal(fileUrl, fileName) {
  const modal = document.getElementById('mesh-viewer-modal');
  if (!modal) return;

  const titleEl = document.getElementById('mesh-viewer-filename');
  const badgeEl = document.getElementById('mesh-viewer-polycount');
  const loadingEl = document.getElementById('mesh-viewer-loading');
  const errorEl = document.getElementById('mesh-viewer-error');
  const canvasWrap = document.getElementById('mesh-viewer-canvas-wrap');

  if (titleEl) titleEl.textContent = fileName || 'Modelo 3D';
  if (badgeEl) badgeEl.textContent = 'Calculando malla...';
  if (errorEl) errorEl.style.display = 'none';
  if (loadingEl) loadingEl.style.display = 'flex';

  modal.style.display = 'flex';
  modal.classList.add('is-open');

  // Limpiar escena previa si existiera
  closeMeshViewerModal(false);

  const format = get3DFormat(fileName);

  try {
    // 1. Obtener datos crudos para estadísticas instantáneas
    const resp = await fetch(fileUrl);
    if (!resp.ok) throw new Error('No se pudo acceder al búfer del archivo.');

    let statsText = '';
    let arrayBuffer = null;

    if (format === 'obj') {
      const text = await resp.text();
      const stats = parseObjStats(text);
      if (badgeEl) badgeEl.textContent = formatPolycount(stats);
      statsText = text;
    } else if (format === 'stl') {
      arrayBuffer = await resp.arrayBuffer();
      const stats = parseStlStats(arrayBuffer);
      if (badgeEl) badgeEl.textContent = formatPolycount(stats);
    } else {
      arrayBuffer = await resp.arrayBuffer();
      if (badgeEl) badgeEl.textContent = 'Malla glTF / GLB';
    }

    // 2. Carga perezosa (Lazy Import) del motor Three.js desde CDN
    const THREE = await import('https://esm.sh/three@0.160.0');
    const { OrbitControls } = await import('https://esm.sh/three@0.160.0/addons/controls/OrbitControls.js');

    // 3. Crear canvas, renderer y escena
    const width = canvasWrap.clientWidth || 800;
    const height = canvasWrap.clientHeight || 550;

    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: false });
    renderer.setSize(width, height);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
    renderer.setClearColor(0x181a20, 1);
    canvasWrap.appendChild(renderer.domElement);

    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(45, width / height, 0.1, 1000);
    const controls = new OrbitControls(camera, renderer.domElement);
    controls.enableDamping = true;
    controls.dampingFactor = 0.05;

    // Iluminación de estudio para modelado 3D (3 puntos)
    const ambientLight = new THREE.AmbientLight(0xffffff, 0.65);
    scene.add(ambientLight);

    const keyLight = new THREE.DirectionalLight(0xffffff, 0.85);
    keyLight.position.set(10, 20, 15);
    scene.add(keyLight);

    const fillLight = new THREE.DirectionalLight(0x94a3b8, 0.45);
    fillLight.position.set(-15, -10, -10);
    scene.add(fillLight);

    // Material tipo arcilla (Clay Viewport)
    const clayMaterial = new THREE.MeshStandardMaterial({
      color: 0x94a3b8,
      roughness: 0.35,
      metalness: 0.08,
      side: THREE.DoubleSide
    });

    const wireframeMaterial = new THREE.MeshBasicMaterial({
      color: 0x38bdf8,
      wireframe: true
    });

    let rootObject = null;
    const wireframes = [];

    // 4. Cargar la geometría según el formato
    if (format === 'obj') {
      const { OBJLoader } = await import('https://esm.sh/three@0.160.0/addons/loaders/OBJLoader.js');
      const loader = new OBJLoader();
      rootObject = loader.parse(statsText);

      rootObject.traverse((child) => {
        if (child.isMesh) {
          child.material = clayMaterial;
          // Crear aristas superpuestas para modo Sólido + Malla
          const wireGeom = new THREE.WireframeGeometry(child.geometry);
          const wireLine = new THREE.LineSegments(wireGeom, wireframeMaterial);
          wireLine.visible = false;
          child.add(wireLine);
          wireframes.push(wireLine);
        }
      });
    } else if (format === 'stl') {
      const { STLLoader } = await import('https://esm.sh/three@0.160.0/addons/loaders/STLLoader.js');
      const loader = new STLLoader();
      const geom = loader.parse(arrayBuffer);
      geom.computeVertexNormals();
      const mesh = new THREE.Mesh(geom, clayMaterial);

      const wireGeom = new THREE.WireframeGeometry(geom);
      const wireLine = new THREE.LineSegments(wireGeom, wireframeMaterial);
      wireLine.visible = false;
      mesh.add(wireLine);
      wireframes.push(wireLine);

      rootObject = new THREE.Group();
      rootObject.add(mesh);
    } else if (format === 'glb' || format === 'gltf') {
      const { GLTFLoader } = await import('https://esm.sh/three@0.160.0/addons/loaders/GLTFLoader.js');
      const loader = new GLTFLoader();
      const gltf = await new Promise((res, rej) => {
        loader.parse(arrayBuffer, '', res, rej);
      });
      rootObject = gltf.scene || gltf.scenes[0];
      rootObject.traverse((child) => {
        if (child.isMesh) {
          const wireGeom = new THREE.WireframeGeometry(child.geometry);
          const wireLine = new THREE.LineSegments(wireGeom, wireframeMaterial);
          wireLine.visible = false;
          child.add(wireLine);
          wireframes.push(wireLine);
        }
      });
    }

    if (!rootObject) throw new Error('Formato de malla no interpretable.');

    // 5. Centrar geometría en el origen y ajustar cámara
    const box = new THREE.Box3().setFromObject(rootObject);
    const center = new THREE.Vector3();
    box.getCenter(center);
    rootObject.position.sub(center);
    scene.add(rootObject);

    const sphere = new THREE.Sphere();
    box.getBoundingSphere(sphere);
    const radius = Math.max(sphere.radius, 0.5);

    camera.position.set(0, radius * 0.8, radius * 2.2);
    camera.near = radius * 0.01;
    camera.far = radius * 100;
    camera.updateProjectionMatrix();

    controls.target.set(0, 0, 0);
    controls.update();

    if (loadingEl) loadingEl.style.display = 'none';

    // 6. Bucle de renderizado
    let animationId = null;
    let isRunning = true;

    function animate() {
      if (!isRunning) return;
      animationId = requestAnimationFrame(animate);
      controls.update();
      renderer.render(scene, camera);
    }
    animate();

    // 7. Redimensionamiento reactivo
    const resizeObserver = new ResizeObserver(() => {
      if (!canvasWrap) return;
      const w = canvasWrap.clientWidth;
      const h = canvasWrap.clientHeight;
      if (w === 0 || h === 0) return;
      camera.aspect = w / h;
      camera.updateProjectionMatrix();
      renderer.setSize(w, h);
    });
    resizeObserver.observe(canvasWrap);

    // Guardar referencia de estado para limpieza o cambios de sombreado
    activeSceneState = {
      renderer,
      scene,
      camera,
      controls,
      rootObject,
      clayMaterial,
      wireframeMaterial,
      wireframes,
      resizeObserver,
      radius,
      stop: () => {
        isRunning = false;
        if (animationId) cancelAnimationFrame(animationId);
        resizeObserver.disconnect();
        renderer.dispose();
        if (renderer.domElement && renderer.domElement.parentNode) {
          renderer.domElement.parentNode.removeChild(renderer.domElement);
        }
      }
    };

  } catch (err) {
    console.error('[MeshViewer] Error cargando modelo:', err);
    if (loadingEl) loadingEl.style.display = 'none';
    if (errorEl) {
      errorEl.textContent = `Error al renderizar malla: ${err.message}. Comprueba que el archivo no esté corrupto.`;
      errorEl.style.display = 'block';
    }
  }
}

/**
 * Cambia el modo de visualización de la malla activa.
 * @param {'clay'|'wireframe'|'both'} mode
 */
export function setShadingMode(mode) {
  if (!activeSceneState) return;
  const { clayMaterial, wireframes } = activeSceneState;

  if (mode === 'clay') {
    clayMaterial.wireframe = false;
    clayMaterial.visible = true;
    wireframes.forEach(w => { w.visible = false; });
  } else if (mode === 'wireframe') {
    clayMaterial.wireframe = true;
    clayMaterial.visible = true;
    wireframes.forEach(w => { w.visible = false; });
  } else if (mode === 'both') {
    clayMaterial.wireframe = false;
    clayMaterial.visible = true;
    wireframes.forEach(w => { w.visible = true; });
  }

  // Actualizar botones de modo en la interfaz
  const buttons = document.querySelectorAll('.btn-mesh-mode');
  buttons.forEach(btn => {
    btn.classList.toggle('is-active', btn.dataset.mode === mode);
  });
}

/**
 * Restaura la cámara al encuadre central predeterminado.
 */
export function resetCameraView() {
  if (!activeSceneState) return;
  const { camera, controls, radius } = activeSceneState;
  camera.position.set(0, radius * 0.8, radius * 2.2);
  controls.target.set(0, 0, 0);
  controls.update();
}

/**
 * Cierra el modal de inspección 3D y libera recursos de memoria WebGL.
 * @param {boolean} [hideModal=true]
 */
export function closeMeshViewerModal(hideModal = true) {
  if (activeSceneState) {
    try {
      activeSceneState.stop();
    } catch {}
    activeSceneState = null;
  }

  if (hideModal) {
    const modal = document.getElementById('mesh-viewer-modal');
    if (modal) {
      modal.style.display = 'none';
      modal.classList.remove('is-open');
    }
  }
}

/**
 * Enlaza los botones de la interfaz del modal 3D (modos, centrado, cierre).
 */
export function setupMeshViewerEvents() {
  const btnClose = document.getElementById('btn-close-mesh-viewer');
  const backdrop = document.getElementById('mesh-viewer-backdrop');
  const btnReset = document.getElementById('btn-mesh-reset-cam');

  btnClose?.addEventListener('click', () => closeMeshViewerModal(true));
  backdrop?.addEventListener('click', () => closeMeshViewerModal(true));
  btnReset?.addEventListener('click', resetCameraView);

  const modeButtons = document.querySelectorAll('.btn-mesh-mode');
  modeButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      const mode = btn.dataset.mode;
      if (mode) setShadingMode(mode);
    });
  });

  // Atajo de teclado ESC para cerrar
  window.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      const modal = document.getElementById('mesh-viewer-modal');
      if (modal && modal.classList.contains('is-open')) {
        closeMeshViewerModal(true);
      }
    }
  });
}
