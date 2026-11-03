/**
 * Stage 1 · InfinityMark
 * One persistent Three.js sculpture and ONE travelling photon.
 * Presentation-only: it never reads credentials, calls APIs or mutates state.
 */
import * as THREE from 'three';

const TWO_PI = Math.PI * 2;
const q = (value, lo, hi) => Math.max(lo, Math.min(hi, value));

function makeCurve() {
  const points = [];
  for (let i = 0; i < 384; i++) {
    const t = TWO_PI * i / 384;
    const sine = Math.sin(t);
    const cosine = Math.cos(t);
    const denom = 1 + sine * sine;
    points.push(new THREE.Vector3(
      3.0 * cosine / denom,
      3.8 * sine * cosine / denom,
      0.28 * Math.sin(t * 2)
    ));
  }
  return new THREE.CatmullRomCurve3(points, true, 'centripetal', 0.5);
}

function createRibbonGeometry(curve, width = 0.28, steps = 640) {
  const frames = curve.computeFrenetFrames(steps, true);
  const vertices = new Float32Array((steps + 1) * 2 * 3);
  const uvs = new Float32Array((steps + 1) * 2 * 2);
  const indices = [];
  const at = (i, j, point) => {
    const index = (i * 2 + j) * 3;
    vertices[index] = point.x;
    vertices[index + 1] = point.y;
    vertices[index + 2] = point.z;
    uvs[(i * 2 + j) * 2] = i / steps;
    uvs[(i * 2 + j) * 2 + 1] = j;
  };
  const edges = [[], []];
  for (let i = 0; i <= steps; i++) {
    const t = i / steps;
    const point = curve.getPointAt(t);
    const twist = 0.25 * Math.sin(TWO_PI * t);
    const side = frames.normals[i].clone().multiplyScalar(Math.cos(twist))
      .addScaledVector(frames.binormals[i], Math.sin(twist)).normalize();
    const left = point.clone().addScaledVector(side, -width / 2);
    const right = point.clone().addScaledVector(side, width / 2);
    at(i, 0, left);
    at(i, 1, right);
    if (i < steps) {
      edges[0].push(left);
      edges[1].push(right);
    }
    if (i < steps) {
      const base = i * 2;
      indices.push(base, base + 1, base + 2, base + 1, base + 3, base + 2);
    }
  }
  const geometry = new THREE.BufferGeometry();
  geometry.setAttribute('position', new THREE.BufferAttribute(vertices, 3));
  geometry.setAttribute('uv', new THREE.BufferAttribute(uvs, 2));
  geometry.setIndex(indices);
  geometry.computeVertexNormals();
  return {
    geometry,
    edgeCurves: edges.map(points => new THREE.CatmullRomCurve3(points, true))
  };
}

function ellipse(radius, y, color, opacity) {
  const curve = new THREE.EllipseCurve(0, 0, radius, radius * 0.23, 0, TWO_PI);
  const points = curve.getPoints(192);
  const geometry = new THREE.BufferGeometry().setFromPoints(
    points.map(p => new THREE.Vector3(p.x, y, p.y))
  );
  const line = new THREE.LineLoop(geometry,
    new THREE.LineBasicMaterial({ color, transparent: true, opacity, depthWrite: false }));
  return line;
}

export class InfinityMark {
  constructor(scene) {
    this.group = new THREE.Group();
    this.group.name = 'JW-INFINITY-SINGLE-SCULPTURE';
    scene.add(this.group);
    this.curve = makeCurve();

    const { geometry, edgeCurves } = createRibbonGeometry(this.curve);
    this.indexLength = geometry.index.count;
    this.ribbon = new THREE.Mesh(geometry, new THREE.MeshPhysicalMaterial({
      color: '#cad7e8',
      side: THREE.DoubleSide,
      metalness: 0.10,     // Metalness 1 is incompatible with true glass transmission.
      roughness: 0.12,
      transmission: 0.72,
      thickness: 0.34,
      ior: 1.45,
      clearcoat: 1,
      clearcoatRoughness: 0.06,
      specularIntensity: 1,
      transparent: false,
      depthWrite: true
    }));
    this.ribbon.name = 'JW-GLASS-RIBBON';
    this.group.add(this.ribbon);

    const edgeMaterial = new THREE.MeshStandardMaterial({
      color: '#e8eff7', metalness: 0.83, roughness: 0.18,
      emissive: '#607b9e', emissiveIntensity: 0.09
    });
    this.edges = edgeCurves.map((c, n) => {
      const obj = new THREE.Mesh(new THREE.TubeGeometry(c, 512, 0.025, 6, true),
        edgeMaterial);
      obj.name = 'JW-METAL-EDGE-' + n;
      this.group.add(obj);
      return obj;
    });

    this.photon = new THREE.Group();
    this.photon.name = 'JW-ONE-PHOTON';
    const core = new THREE.Mesh(new THREE.SphereGeometry(0.065, 12, 8),
      new THREE.MeshBasicMaterial({ color: '#ffffff', toneMapped: false }));
    const glow = new THREE.Sprite(new THREE.SpriteMaterial({
      color: '#c5dafa', transparent: true, opacity: 0.55, blending: THREE.AdditiveBlending,
      depthWrite: false
    }));
    glow.scale.set(0.36, 0.36, 1);
    this.photon.add(glow, core);
    this.group.add(this.photon);

    this.light = new THREE.PointLight('#d7e9ff', 3.2, 2.5, 2);
    this.photon.add(this.light);

    const trailPoints = new Float32Array(64 * 3);
    this.trailGeometry = new THREE.BufferGeometry();
    this.trailGeometry.setAttribute('position',
      new THREE.BufferAttribute(trailPoints, 3).setUsage(THREE.DynamicDrawUsage));
    this.trail = new THREE.Line(this.trailGeometry, new THREE.LineBasicMaterial({
      color: '#c3d7f3', transparent: true, opacity: 0.38, depthWrite: false
    }));
    this.trail.frustumCulled = false;
    this.group.add(this.trail);

    this.rings = [
      ellipse(2.28, -1.42, '#c7d4e5', 0.29),
      ellipse(1.84, -1.44, '#a4c0de', 0.21),
      ellipse(1.42, -1.46, '#e6edf7', 0.13)
    ];
    for (const ring of this.rings) this.group.add(ring);

    this.orbit = new THREE.Group();
    this.orbit.name = 'JW-LOGIN-ORBIT';
    this.group.add(this.orbit);
    for (let i = 0; i < 2; i++) {
      const orbit = ellipse(2.58 + i * 0.43, -0.04, '#b9cee7', 0.08 - i * 0.015);
      orbit.rotation.x = 0.15 + i * 0.23;
      orbit.rotation.z = -0.11 + i * 0.18;
      this.orbit.add(orbit);
    }
    this.phase = 0.13;
    this.drawFraction = 1;
    this.tick(0, 0, 'login', true);
  }

  setReveal(fraction) {
    this.drawFraction = q(fraction, 0, 1);
    const triangles = Math.floor(this.drawFraction * this.indexLength / 3);
    this.ribbon.geometry.setDrawRange(0, triangles * 3);
    for (const edge of this.edges) edge.visible = this.drawFraction > 0.94;
    this.photon.visible = this.drawFraction > 0.02;
  }

  tick(dt, time, state, reduced = false) {
    if (!reduced) this.phase = (this.phase + Math.min(dt, 0.06) / 9) % 1;
    const point = this.curve.getPointAt(this.phase);
    this.photon.position.copy(point);
    const array = this.trailGeometry.attributes.position.array;
    for (let i = 0; i < 64; i++) {
      const p = this.curve.getPointAt((this.phase - i * 0.00027 + 1) % 1);
      array[i * 3] = p.x;
      array[i * 3 + 1] = p.y;
      array[i * 3 + 2] = p.z + 0.004;
    }
    this.trailGeometry.attributes.position.needsUpdate = true;
    this.orbit.visible = state === 'login' || state === 'transition';
    this.orbit.rotation.y = reduced ? 0 : Math.sin(time * Math.PI / 10) * 0.04;
    // The object drifts less than two degrees; no bounce or spring overshoot.
    this.ribbon.rotation.y = reduced ? 0 : 0.026 * Math.sin(time * Math.PI / 10);
    this.ribbon.rotation.x = reduced ? 0 : 0.012 * Math.cos(time * Math.PI / 10);
  }

  dispose() {
    const disposed = new Set();
    this.group.traverse(o => {
      if (o.geometry) o.geometry.dispose();
      if (o.material) {
        const materials = Array.isArray(o.material) ? o.material : [o.material];
        for (const m of materials) if (!disposed.has(m)) {
          m.dispose();
          disposed.add(m);
        }
      }
    });
    this.group.parent?.remove(this.group);
  }
}
