#ifndef __VPU_LOG_H__
#define __VPU_LOG_H__

#define ALOG_TAG "VPU"

//#define _VPU_MEM_DEUBG
//#define _VPU_MEM_ERROR
//#define _VPU_MEM_INFO

#ifdef _VPU_MEM_DEUBG
#define VPM_DEBUG(fmt, args...) ALOGD(fmt, ## args)
#else
#define VPM_DEBUG(fmt, args...) /* do nothing */
#endif

#ifdef _VPU_MEM_ERROR
#define VPM_ERROR(fmt, args...) ALOGE(fmt, ## args)
#else
#define VPM_ERROR(fmt, args...)
#endif

#ifdef _VPU_MEM_INFO
#define VPM_INFO(fmt, args...) ALOGI(fmt, ## args)
#else
#define VPM_INFO(fmt, args...)
#endif

#endif


