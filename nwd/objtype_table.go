package nwd

// objTypeNames maps NwObjectType IDs to their reader class object names.
// Extracted from TNW_Db.tx registerObjectReaders GOT relocations (E2,
// findings N20): 110 of 201 slots registered.
var objTypeNames = map[int]string{
	1: "OdNwStaticTreeGroup",
	2: "OdNwStaticTreeLeaf",
	13: "OdNwFragment",
	14: "OdNwObjTranslation",
	15: "OdNwObjTransRot",
	16: "OdNwObjTransRotScale",
	17: "OdNwObjMatrix",
	22: "OdNwGeometryModelItemNode",
	27: "OdNwDistantLight",
	28: "OdNwPointLight",
	29: "OdNwSpotLight",
	31: "OdNwMaterialAttribute",
	32: "OdNwPartitionNode",
	39: "OdNwTransformAttribute",
	40: "OdNwTransAttribute",
	41: "OdNwTransRotationAttribute",
	52: "OdNwName",
	53: "OdNwGroupModelItemNode",
	54: "OdNwGraphicMaterial",
	55: "OdNwGraphicAppearance",
	58: "OdNwGraphicColorSet",
	59: "OdNwGraphicNormalSetFloat",
	60: "OdNwGraphicVertexSet",
	61: "OdNwGraphicTexCoordSet",
	62: "OdNwGraphicTriangleSet",
	66: "OdNwUInt64Attribute",
	70: "OdNwNameAttribute",
	72: "OdNwObjTransDynamic",
	73: "OdNwRunPath",
	76: "OdNwTextAttribute",
	79: "OdNwURLAttribute",
	80: "OdNwGraphicPointSet",
	81: "OdNwGraphicLineSet",
	86: "OdNwPropertyAttribute",
	88: "OdNwBinaryAttribute",
	89: "OdNwElementRecord",
	92: "OdNwPublishAttribute",
	93: "OdNwGraphicGeometryRef",
	94: "OdNwGraphicTriangleSetElement",
	95: "OdNwGraphicLineSetElement",
	96: "OdNwGraphicPointSetElement",
	97: "OdNwPresenterMaterialAttribute",
	98: "OdNwPresenterTextureSpaceAttribute",
	100: "OdNwGraphicNormalSetShort",
	102: "OdNwTextStyle",
	103: "OdNwGraphicTextElement",
	104: "OdNwGraphicCircleElement",
	105: "OdNwGraphicCylinderElement",
	106: "OdNwPlotGeometryAttribute",
	107: "OdNwPlotPaperAttribute",
	108: "OdNwPlotEmbeddedFontsAttribute",
	109: "OdNwPlotTransform",
	110: "OdNwPlotAppearance",
	111: "OdNwPlotArcSegment",
	112: "OdNwPlotCanvas",
	113: "OdNwPlotCanvasStyle",
	114: "OdNwPlotCircleSegment",
	115: "OdNwPlotColor",
	116: "OdNwPlotEllipseSegment",
	117: "OdNwPlotEmbeddedFont",
	118: "OdNwPlotFontStyle",
	119: "OdNwPlotGeometryBrush",
	120: "OdNwPlotGeometryStream",
	121: "OdNwPlotHatchBrush",
	122: "OdNwPlotImageBrush",
	123: "OdNwPlotImageHeader",
	124: "OdNwPlotLinearGradientBrush",
	125: "OdNwPlotPaperStyle",
	126: "OdNwPlotPath",
	127: "OdNwPlotPathFigure",
	128: "OdNwPlotPathFigureStyle",
	129: "OdNwPlotPathStreamStyle",
	130: "OdNwPlotPathStyle",
	131: "OdNwPlotSegmentOfPoints",
	132: "OdNwPlotPointListSegment",
	133: "OdNwPlotPolyBezierSegment",
	134: "OdNwPlotPolyLineSegment",
	135: "OdNwPlotPolyQuadraticBezierSegment",
	136: "OdNwPlotPolyTriangle",
	137: "OdNwPlotRadialGradientBrush",
	138: "OdNwPlotResource",
	139: "OdNwPlotSolidColorBrush",
	140: "OdNwPlotStream",
	141: "OdNwPlotStreamEntry",
	142: "OdNwPlotStreamEntryContainer",
	143: "OdNwPlotStroke",
	144: "OdNwPlotText",
	145: "OdNwPlotTextLine",
	146: "OdNwPlotTextStyle",
	147: "OdNwPlotTransform2",
	148: "OdNwPlotVertexColorBrush",
	149: "OdNwPlotViewport",
	168: "OdNwPlotViewportStyle",
	169: "OdNwPlotCoreShape",
	170: "OdNwPlotGeomRef",
	171: "OdNwPlotCoreShapeRepresentation",
	172: "OdNwPlotCoreShapePathFigure",
	173: "OdNwPlotPathFigure2",
	174: "OdNwPlotSegment",
	175: "OdNwPlotCoreShapeText",
	176: "OdNwPlotPathFigureAppearance",
	177: "OdNwPlotTextAppearance",
	178: "OdNwPlotBrush",
	179: "OdNwPlotHatchPattern",
	180: "OdNwGuidAttribute",
	181: "OdNwGraphicExternalGeometry",
	182: "OdNwGraphicBundle",
	183: "OdNwGraphicBundleSchema",
	185: "OdNwGraphicJsonBundle",
	200: "OdNwGraphicMaterialAttribute",
}

// ObjTypeName returns the registered object type name for id, or "" if
// the slot is unregistered.
func ObjTypeName(id int) string { return objTypeNames[id] }

// Known object type IDs used by the model-tree layer (findings N20).
const (
	TypeStaticTreeGroup      = 1
	TypeStaticTreeLeaf       = 2
	TypeFragment             = 13
	TypeGeometryModelItem    = 22
	TypePartitionNode        = 32
	TypeName                 = 52
	TypeGroupModelItemNode   = 53
	TypeElementRecord        = 89
)

// Short aliases used by decoders.
const (
	PartitionNode      = TypePartitionNode
	GroupModelItemNode = TypeGroupModelItemNode
)
