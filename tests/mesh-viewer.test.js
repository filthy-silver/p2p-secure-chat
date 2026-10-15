/**
 * @file tests/mesh-viewer.test.js
 * @description Pruebas unitarias para el analizador de topología 3D (.obj, .stl) y utilidades de inspección.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import {
  isInspectable3D,
  get3DFormat,
  parseObjStats,
  parseStlStats,
  formatPolycount
} from '../src/chat/mesh-viewer.js';

describe('chat/mesh-viewer.js · Analizador de Mallas y Estadísticas 3D', () => {

  describe('isInspectable3D() y get3DFormat()', () => {
    it('detecta correctamente formatos 3D compatibles (obj, stl, glb, gltf)', () => {
      assert.equal(isInspectable3D('personaje.obj'), true);
      assert.equal(isInspectable3D('ESCULTURA.OBJ'), true);
      assert.equal(isInspectable3D('pieza_mecanica.stl'), true);
      assert.equal(isInspectable3D('animacion.glb'), true);
      assert.equal(isInspectable3D('escena.gltf'), true);

      assert.equal(get3DFormat('personaje.obj'), 'obj');
      assert.equal(get3DFormat('pieza.STL'), 'stl');
      assert.equal(get3DFormat('asset.glb'), 'glb');
      assert.equal(get3DFormat('modelo.gltf'), 'gltf');
    });

    it('rechaza archivos que no sean mallas directas (blend, fbx, zip, png, vacios)', () => {
      assert.equal(isInspectable3D('proyecto.blend'), false);
      assert.equal(isInspectable3D('rig_autodesk.fbx'), false);
      assert.equal(isInspectable3D('texturas.zip'), false);
      assert.equal(isInspectable3D('render.png'), false);
      assert.equal(isInspectable3D(''), false);
      assert.equal(isInspectable3D(null), false);
      assert.equal(isInspectable3D(undefined), false);

      assert.equal(get3DFormat('proyecto.blend'), null);
      assert.equal(get3DFormat(''), null);
      assert.equal(get3DFormat(null), null);
    });
  });

  describe('parseObjStats() · Desglose de Topología Wavefront OBJ', () => {
    it('analiza un cubo estructurado en Quads (4 vértices por cara)', () => {
      const objQuadCube = `
# Cubo simple en quads
v 0 0 0
v 1 0 0
v 1 1 0
v 0 1 0
v 0 0 1
v 1 0 1
v 1 1 1
v 0 1 1
vn 0 0 1
vt 0.5 0.5
f 1/1/1 2/1/1 3/1/1 4/1/1
f 5/1/1 6/1/1 7/1/1 8/1/1
`;
      const stats = parseObjStats(objQuadCube);
      assert.equal(stats.vertices, 8);
      assert.equal(stats.normals, 1);
      assert.equal(stats.uvs, 1);
      assert.equal(stats.faces, 2);
      assert.equal(stats.quads, 2);
      assert.equal(stats.triangles, 4); // 2 quads = 4 triángulos
      assert.equal(stats.ngons, 0);
      assert.equal(stats.hasNormals, true);
      assert.equal(stats.hasUvs, true);
    });

    it('analiza mallas trianguladas estándar', () => {
      const objTriangles = `
v 0 0 0
v 1 0 0
v 0 1 0
v 1 1 0
f 1 2 3
f 2 4 3
`;
      const stats = parseObjStats(objTriangles);
      assert.equal(stats.vertices, 4);
      assert.equal(stats.faces, 2);
      assert.equal(stats.triangles, 2);
      assert.equal(stats.quads, 0);
      assert.equal(stats.ngons, 0);
      assert.equal(stats.hasNormals, false);
      assert.equal(stats.hasUvs, false);
    });

    it('detecta polígonos no deseados (N-Gons con más de 4 vértices)', () => {
      const objNgon = `
v 0 0 0
v 1 0 0
v 2 1 0
v 1 2 0
v 0 2 0
f 1 2 3 4 5
`;
      const stats = parseObjStats(objNgon);
      assert.equal(stats.vertices, 5);
      assert.equal(stats.faces, 1);
      assert.equal(stats.quads, 0);
      assert.equal(stats.ngons, 1);
      assert.equal(stats.triangles, 3); // Pentágono = 5 - 2 = 3 tris
    });

    it('maneja entradas vacías o nulas sin lanzar excepciones', () => {
      const stats = parseObjStats('');
      assert.equal(stats.vertices, 0);
      assert.equal(stats.faces, 0);
      assert.equal(stats.triangles, 0);

      const nullStats = parseObjStats(null);
      assert.equal(nullStats.vertices, 0);
    });
  });

  describe('parseStlStats() · Mallas de Impresión 3D STL', () => {
    it('detecta y parsea un archivo binario STL con cabecera exacta de 84 + (N * 50) bytes', () => {
      // 2 triángulos = 84 + 100 = 184 bytes
      const buffer = new ArrayBuffer(184);
      const view = new DataView(buffer);
      view.setUint32(80, 2, true); // 2 facetas

      const stats = parseStlStats(buffer);
      assert.equal(stats.isBinary, true);
      assert.equal(stats.triangles, 2);
      assert.equal(stats.vertices, 6);
    });

    it('parsea un archivo ASCII STL contando facetas normales', () => {
      const asciiStl = `solid prueba
  facet normal 0 0 1
    outer loop
      vertex 0 0 0
      vertex 1 0 0
      vertex 1 1 0
    endloop
  endfacet
  facet normal 0 0 1
    outer loop
      vertex 0 0 0
      vertex 1 1 0
      vertex 0 1 0
    endloop
  endfacet
endsolid prueba`;

      const encoder = new TextEncoder();
      const buffer = encoder.encode(asciiStl).buffer;

      const stats = parseStlStats(buffer);
      assert.equal(stats.isBinary, false);
      assert.equal(stats.triangles, 2);
      assert.equal(stats.vertices, 6);
    });

    it('devuelve conteo cero ante buffers truncados o nulos', () => {
      const empty = parseStlStats(null);
      assert.equal(empty.triangles, 0);

      const shortBuf = new ArrayBuffer(50);
      const stats = parseStlStats(shortBuf);
      assert.equal(stats.triangles, 0);
    });
  });

  describe('formatPolycount()', () => {
    it('formatea correctamente números de vértices, triángulos y quads', () => {
      const statsQuad = { vertices: 12500, triangles: 24800, quads: 12400 };
      const str = formatPolycount(statsQuad);
      assert.ok(str.includes('12.500') || str.includes('12500'));
      assert.ok(str.includes('24.800') || str.includes('24800'));
      assert.ok(str.includes('Quads'));

      const statsTri = { vertices: 300, triangles: 500, quads: 0 };
      const strTri = formatPolycount(statsTri);
      assert.ok(strTri.includes('Vértices') || strTri.includes('V:'));
      assert.ok(!strTri.includes('Quads'));
    });
  });

});
