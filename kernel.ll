; ModuleID = 'kernel.c'
source_filename = "kernel.c"
target datalayout = "e-m:e-p:64:64-i64:64-n32:64-S128"
target triple = "bpf"

%struct.bpf_map_def = type { i32, i32, i32, i32, i32 }
%struct.xdp_md = type { i32, i32, i32, i32, i32 }
%struct.ethhdr = type { [6 x i8], [6 x i8], i16 }

@xsks_map = dso_local global %struct.bpf_map_def { i32 17, i32 4, i32 4, i32 64, i32 0 }, section "maps", align 4, !dbg !0
@_license = dso_local global [4 x i8] c"GPL\00", section "license", align 1, !dbg !21
@llvm.used = appending global [3 x i8*] [i8* getelementptr inbounds ([4 x i8], [4 x i8]* @_license, i32 0, i32 0), i8* bitcast (i32 (%struct.xdp_md*)* @xdp_sock_prog to i8*), i8* bitcast (%struct.bpf_map_def* @xsks_map to i8*)], section "llvm.metadata"

; Function Attrs: nounwind
define dso_local i32 @xdp_sock_prog(%struct.xdp_md* nocapture readonly %0) #0 section "xdp_sock" !dbg !56 {
  %2 = alloca i32, align 4
  call void @llvm.dbg.value(metadata %struct.xdp_md* %0, metadata !69, metadata !DIExpression()), !dbg !89
  %3 = bitcast i32* %2 to i8*, !dbg !90
  call void @llvm.lifetime.start.p0i8(i64 4, i8* nonnull %3) #3, !dbg !90
  %4 = getelementptr inbounds %struct.xdp_md, %struct.xdp_md* %0, i64 0, i32 4, !dbg !91
  %5 = load i32, i32* %4, align 4, !dbg !91, !tbaa !92
  call void @llvm.dbg.value(metadata i32 %5, metadata !70, metadata !DIExpression()), !dbg !89
  store i32 %5, i32* %2, align 4, !dbg !97, !tbaa !98
  %6 = getelementptr inbounds %struct.xdp_md, %struct.xdp_md* %0, i64 0, i32 0, !dbg !99
  %7 = load i32, i32* %6, align 4, !dbg !99, !tbaa !100
  %8 = zext i32 %7 to i64, !dbg !101
  %9 = inttoptr i64 %8 to i8*, !dbg !102
  call void @llvm.dbg.value(metadata i8* %9, metadata !71, metadata !DIExpression()), !dbg !89
  %10 = getelementptr inbounds %struct.xdp_md, %struct.xdp_md* %0, i64 0, i32 1, !dbg !103
  %11 = load i32, i32* %10, align 4, !dbg !103, !tbaa !104
  %12 = zext i32 %11 to i64, !dbg !105
  %13 = inttoptr i64 %12 to i8*, !dbg !106
  call void @llvm.dbg.value(metadata i8* %13, metadata !72, metadata !DIExpression()), !dbg !89
  call void @llvm.dbg.value(metadata i8* %9, metadata !73, metadata !DIExpression()), !dbg !89
  call void @llvm.dbg.value(metadata i32 14, metadata !88, metadata !DIExpression()), !dbg !89
  %14 = getelementptr i8, i8* %9, i64 14, !dbg !107
  %15 = icmp ugt i8* %14, %13, !dbg !109
  br i1 %15, label %28, label %16, !dbg !110

16:                                               ; preds = %1
  %17 = inttoptr i64 %8 to %struct.ethhdr*, !dbg !111
  call void @llvm.dbg.value(metadata %struct.ethhdr* %17, metadata !73, metadata !DIExpression()), !dbg !89
  %18 = getelementptr inbounds %struct.ethhdr, %struct.ethhdr* %17, i64 0, i32 2, !dbg !112
  %19 = load i16, i16* %18, align 1, !dbg !112, !tbaa !114
  %20 = icmp eq i16 %19, -8826, !dbg !117
  br i1 %20, label %21, label %28, !dbg !117

21:                                               ; preds = %16
  call void @llvm.dbg.value(metadata i32* %2, metadata !70, metadata !DIExpression(DW_OP_deref)), !dbg !89
  %22 = call i8* inttoptr (i64 1 to i8* (i8*, i8*)*)(i8* bitcast (%struct.bpf_map_def* @xsks_map to i8*), i8* nonnull %3) #3, !dbg !118
  %23 = icmp eq i8* %22, null, !dbg !118
  br i1 %23, label %28, label %24, !dbg !122

24:                                               ; preds = %21
  %25 = load i32, i32* %2, align 4, !dbg !123, !tbaa !98
  call void @llvm.dbg.value(metadata i32 %25, metadata !70, metadata !DIExpression()), !dbg !89
  %26 = call i64 inttoptr (i64 51 to i64 (i8*, i32, i64)*)(i8* bitcast (%struct.bpf_map_def* @xsks_map to i8*), i32 %25, i64 0) #3, !dbg !124
  %27 = trunc i64 %26 to i32, !dbg !124
  br label %28, !dbg !125

28:                                               ; preds = %16, %21, %1, %24
  %29 = phi i32 [ %27, %24 ], [ 2, %1 ], [ 2, %21 ], [ 2, %16 ], !dbg !89
  call void @llvm.lifetime.end.p0i8(i64 4, i8* nonnull %3) #3, !dbg !126
  ret i32 %29, !dbg !126
}

; Function Attrs: argmemonly nounwind willreturn
declare void @llvm.lifetime.start.p0i8(i64 immarg, i8* nocapture) #1

; Function Attrs: argmemonly nounwind willreturn
declare void @llvm.lifetime.end.p0i8(i64 immarg, i8* nocapture) #1

; Function Attrs: nounwind readnone speculatable willreturn
declare void @llvm.dbg.value(metadata, metadata, metadata) #2

attributes #0 = { nounwind "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "frame-pointer"="all" "less-precise-fpmad"="false" "min-legal-vector-width"="0" "no-infs-fp-math"="false" "no-jump-tables"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="false" "stack-protector-buffer-size"="8" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #1 = { argmemonly nounwind willreturn }
attributes #2 = { nounwind readnone speculatable willreturn }
attributes #3 = { nounwind }

!llvm.dbg.cu = !{!2}
!llvm.module.flags = !{!52, !53, !54}
!llvm.ident = !{!55}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "xsks_map", scope: !2, file: !3, line: 18, type: !44, isLocal: false, isDefinition: true)
!2 = distinct !DICompileUnit(language: DW_LANG_C99, file: !3, producer: "clang version 10.0.0-4ubuntu1 ", isOptimized: true, runtimeVersion: 0, emissionKind: FullDebug, enums: !4, retainedTypes: !14, globals: !20, splitDebugInlining: false, nameTableKind: None)
!3 = !DIFile(filename: "kernel.c", directory: "/root/sra/xsk_srv6_46/xsk_srv6")
!4 = !{!5}
!5 = !DICompositeType(tag: DW_TAG_enumeration_type, name: "xdp_action", file: !6, line: 3150, baseType: !7, size: 32, elements: !8)
!6 = !DIFile(filename: "/usr/include/linux/bpf.h", directory: "")
!7 = !DIBasicType(name: "unsigned int", size: 32, encoding: DW_ATE_unsigned)
!8 = !{!9, !10, !11, !12, !13}
!9 = !DIEnumerator(name: "XDP_ABORTED", value: 0, isUnsigned: true)
!10 = !DIEnumerator(name: "XDP_DROP", value: 1, isUnsigned: true)
!11 = !DIEnumerator(name: "XDP_PASS", value: 2, isUnsigned: true)
!12 = !DIEnumerator(name: "XDP_TX", value: 3, isUnsigned: true)
!13 = !DIEnumerator(name: "XDP_REDIRECT", value: 4, isUnsigned: true)
!14 = !{!15, !16, !17}
!15 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: null, size: 64)
!16 = !DIBasicType(name: "long int", size: 64, encoding: DW_ATE_signed)
!17 = !DIDerivedType(tag: DW_TAG_typedef, name: "__uint16_t", file: !18, line: 40, baseType: !19)
!18 = !DIFile(filename: "/usr/include/bits/types.h", directory: "")
!19 = !DIBasicType(name: "unsigned short", size: 16, encoding: DW_ATE_unsigned)
!20 = !{!0, !21, !27, !35}
!21 = !DIGlobalVariableExpression(var: !22, expr: !DIExpression())
!22 = distinct !DIGlobalVariable(name: "_license", scope: !2, file: !3, line: 89, type: !23, isLocal: false, isDefinition: true)
!23 = !DICompositeType(tag: DW_TAG_array_type, baseType: !24, size: 32, elements: !25)
!24 = !DIBasicType(name: "char", size: 8, encoding: DW_ATE_signed_char)
!25 = !{!26}
!26 = !DISubrange(count: 4)
!27 = !DIGlobalVariableExpression(var: !28, expr: !DIExpression())
!28 = distinct !DIGlobalVariable(name: "bpf_map_lookup_elem", scope: !2, file: !29, line: 50, type: !30, isLocal: true, isDefinition: true)
!29 = !DIFile(filename: "/usr/include/bpf/bpf_helper_defs.h", directory: "")
!30 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !31, size: 64)
!31 = !DISubroutineType(types: !32)
!32 = !{!15, !15, !33}
!33 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !34, size: 64)
!34 = !DIDerivedType(tag: DW_TAG_const_type, baseType: null)
!35 = !DIGlobalVariableExpression(var: !36, expr: !DIExpression())
!36 = distinct !DIGlobalVariable(name: "bpf_redirect_map", scope: !2, file: !29, line: 1295, type: !37, isLocal: true, isDefinition: true)
!37 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !38, size: 64)
!38 = !DISubroutineType(types: !39)
!39 = !{!16, !15, !40, !42}
!40 = !DIDerivedType(tag: DW_TAG_typedef, name: "__u32", file: !41, line: 27, baseType: !7)
!41 = !DIFile(filename: "/usr/include/asm-generic/int-ll64.h", directory: "")
!42 = !DIDerivedType(tag: DW_TAG_typedef, name: "__u64", file: !41, line: 31, baseType: !43)
!43 = !DIBasicType(name: "long long unsigned int", size: 64, encoding: DW_ATE_unsigned)
!44 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "bpf_map_def", file: !45, line: 138, size: 160, elements: !46)
!45 = !DIFile(filename: "/usr/include/bpf/bpf_helpers.h", directory: "")
!46 = !{!47, !48, !49, !50, !51}
!47 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !44, file: !45, line: 139, baseType: !7, size: 32)
!48 = !DIDerivedType(tag: DW_TAG_member, name: "key_size", scope: !44, file: !45, line: 140, baseType: !7, size: 32, offset: 32)
!49 = !DIDerivedType(tag: DW_TAG_member, name: "value_size", scope: !44, file: !45, line: 141, baseType: !7, size: 32, offset: 64)
!50 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !44, file: !45, line: 142, baseType: !7, size: 32, offset: 96)
!51 = !DIDerivedType(tag: DW_TAG_member, name: "map_flags", scope: !44, file: !45, line: 143, baseType: !7, size: 32, offset: 128)
!52 = !{i32 7, !"Dwarf Version", i32 4}
!53 = !{i32 2, !"Debug Info Version", i32 3}
!54 = !{i32 1, !"wchar_size", i32 4}
!55 = !{!"clang version 10.0.0-4ubuntu1 "}
!56 = distinct !DISubprogram(name: "xdp_sock_prog", scope: !3, file: !3, line: 54, type: !57, scopeLine: 54, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !2, retainedNodes: !68)
!57 = !DISubroutineType(types: !58)
!58 = !{!59, !60}
!59 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!60 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !61, size: 64)
!61 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "xdp_md", file: !6, line: 3161, size: 160, elements: !62)
!62 = !{!63, !64, !65, !66, !67}
!63 = !DIDerivedType(tag: DW_TAG_member, name: "data", scope: !61, file: !6, line: 3162, baseType: !40, size: 32)
!64 = !DIDerivedType(tag: DW_TAG_member, name: "data_end", scope: !61, file: !6, line: 3163, baseType: !40, size: 32, offset: 32)
!65 = !DIDerivedType(tag: DW_TAG_member, name: "data_meta", scope: !61, file: !6, line: 3164, baseType: !40, size: 32, offset: 64)
!66 = !DIDerivedType(tag: DW_TAG_member, name: "ingress_ifindex", scope: !61, file: !6, line: 3166, baseType: !40, size: 32, offset: 96)
!67 = !DIDerivedType(tag: DW_TAG_member, name: "rx_queue_index", scope: !61, file: !6, line: 3167, baseType: !40, size: 32, offset: 128)
!68 = !{!69, !70, !71, !72, !73, !88}
!69 = !DILocalVariable(name: "ctx", arg: 1, scope: !56, file: !3, line: 54, type: !60)
!70 = !DILocalVariable(name: "index", scope: !56, file: !3, line: 56, type: !59)
!71 = !DILocalVariable(name: "pkt", scope: !56, file: !3, line: 57, type: !15)
!72 = !DILocalVariable(name: "data_end", scope: !56, file: !3, line: 58, type: !15)
!73 = !DILocalVariable(name: "eth", scope: !56, file: !3, line: 59, type: !74)
!74 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !75, size: 64)
!75 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "ethhdr", file: !76, line: 163, size: 112, elements: !77)
!76 = !DIFile(filename: "/usr/include/linux/if_ether.h", directory: "")
!77 = !{!78, !83, !84}
!78 = !DIDerivedType(tag: DW_TAG_member, name: "h_dest", scope: !75, file: !76, line: 164, baseType: !79, size: 48)
!79 = !DICompositeType(tag: DW_TAG_array_type, baseType: !80, size: 48, elements: !81)
!80 = !DIBasicType(name: "unsigned char", size: 8, encoding: DW_ATE_unsigned_char)
!81 = !{!82}
!82 = !DISubrange(count: 6)
!83 = !DIDerivedType(tag: DW_TAG_member, name: "h_source", scope: !75, file: !76, line: 165, baseType: !79, size: 48, offset: 48)
!84 = !DIDerivedType(tag: DW_TAG_member, name: "h_proto", scope: !75, file: !76, line: 166, baseType: !85, size: 16, offset: 96)
!85 = !DIDerivedType(tag: DW_TAG_typedef, name: "__be16", file: !86, line: 25, baseType: !87)
!86 = !DIFile(filename: "/usr/include/linux/types.h", directory: "")
!87 = !DIDerivedType(tag: DW_TAG_typedef, name: "__u16", file: !41, line: 24, baseType: !19)
!88 = !DILocalVariable(name: "hdrsize", scope: !56, file: !3, line: 63, type: !59)
!89 = !DILocation(line: 0, scope: !56)
!90 = !DILocation(line: 56, column: 5, scope: !56)
!91 = !DILocation(line: 56, column: 22, scope: !56)
!92 = !{!93, !94, i64 16}
!93 = !{!"xdp_md", !94, i64 0, !94, i64 4, !94, i64 8, !94, i64 12, !94, i64 16}
!94 = !{!"int", !95, i64 0}
!95 = !{!"omnipotent char", !96, i64 0}
!96 = !{!"Simple C/C++ TBAA"}
!97 = !DILocation(line: 56, column: 9, scope: !56)
!98 = !{!94, !94, i64 0}
!99 = !DILocation(line: 57, column: 38, scope: !56)
!100 = !{!93, !94, i64 0}
!101 = !DILocation(line: 57, column: 26, scope: !56)
!102 = !DILocation(line: 57, column: 17, scope: !56)
!103 = !DILocation(line: 58, column: 43, scope: !56)
!104 = !{!93, !94, i64 4}
!105 = !DILocation(line: 58, column: 31, scope: !56)
!106 = !DILocation(line: 58, column: 22, scope: !56)
!107 = !DILocation(line: 65, column: 13, scope: !108)
!108 = distinct !DILexicalBlock(scope: !56, file: !3, line: 65, column: 9)
!109 = !DILocation(line: 65, column: 23, scope: !108)
!110 = !DILocation(line: 65, column: 9, scope: !56)
!111 = !DILocation(line: 59, column: 26, scope: !56)
!112 = !DILocation(line: 67, column: 14, scope: !113)
!113 = distinct !DILexicalBlock(scope: !56, file: !3, line: 67, column: 9)
!114 = !{!115, !116, i64 12}
!115 = !{!"ethhdr", !95, i64 0, !95, i64 6, !116, i64 12}
!116 = !{!"short", !95, i64 0}
!117 = !DILocation(line: 67, column: 9, scope: !56)
!118 = !DILocation(line: 80, column: 13, scope: !119)
!119 = distinct !DILexicalBlock(scope: !120, file: !3, line: 80, column: 13)
!120 = distinct !DILexicalBlock(scope: !121, file: !3, line: 70, column: 44)
!121 = distinct !DILexicalBlock(scope: !56, file: !3, line: 70, column: 9)
!122 = !DILocation(line: 80, column: 13, scope: !120)
!123 = !DILocation(line: 81, column: 48, scope: !119)
!124 = !DILocation(line: 81, column: 20, scope: !119)
!125 = !DILocation(line: 81, column: 13, scope: !119)
!126 = !DILocation(line: 87, column: 1, scope: !56)
