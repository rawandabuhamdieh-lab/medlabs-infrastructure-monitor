import { Language } from '../types/infrastructure';

export const COPY: Record<
  Language,
  {
    brandTitle: string;
    brandSub: string;
    nav: {
      dashboard: string;
      servers: string;
      oracle: string;
      iis: string;
      network: string;
      backups: string;
      alerts: string;
      analytics: string;
      users: string;
      architecture: string;
    };
    header: {
      orgCrumb: string;
      signIn: string;
      claimAdmin: string;
      signOut: string;
      roleLabel: string;
      readOnlyBanner: string;
    };
    status: {
      Online: string;
      Warning: string;
      Critical: string;
      Offline: string;
    };
    severity: {
      Critical: string;
      High: string;
      Medium: string;
      Low: string;
      Information: string;
    };
    incidentStatus: {
      Open: string;
      Acknowledged: string;
      'In Progress': string;
      Resolved: string;
    };
    common: {
      search: string;
      all: string;
      lastCheck: string;
      actions: string;
      refresh: string;
      copy: string;
      copied: string;
      save: string;
      cancel: string;
      close: string;
      noResults: string;
    };
  }
> = {
  en: {
    brandTitle: 'MedLabs Infrastructure',
    brandSub: 'IT Intelligence · Jordan',
    nav: {
      dashboard: 'Executive Dashboard',
      servers: 'Windows Servers',
      oracle: 'Oracle Database',
      iis: 'IIS & Applications',
      network: 'Network',
      backups: 'Backups',
      alerts: 'Alerts & Incidents',
      analytics: 'Analytics & Intelligence',
      users: 'Users & Audit Logs',
      architecture: 'Collectors & .NET Kit',
    },
    header: {
      orgCrumb: 'MedLabs Consultancy Group · Jordan',
      signIn: 'Sign In',
      claimAdmin: 'Claim Admin Setup',
      signOut: 'Sign Out',
      roleLabel: 'Role',
      readOnlyBanner: 'Read-only preview session — Sign in as Engineer, Manager, or Administrator to modify incidents, thresholds, or users.',
    },
    status: {
      Online: 'Online',
      Warning: 'Warning',
      Critical: 'Critical',
      Offline: 'Offline',
    },
    severity: {
      Critical: 'Critical',
      High: 'High',
      Medium: 'Medium',
      Low: 'Low',
      Information: 'Information',
    },
    incidentStatus: {
      Open: 'Open',
      Acknowledged: 'Acknowledged',
      'In Progress': 'In Progress',
      Resolved: 'Resolved',
    },
    common: {
      search: 'Search...',
      all: 'All',
      lastCheck: 'Last Check',
      actions: 'Actions',
      refresh: 'Poll Collectors',
      copy: 'Copy Code',
      copied: 'Copied',
      save: 'Save',
      cancel: 'Cancel',
      close: 'Close',
      noResults: 'No matching records found.',
    },
  },
  ar: {
    brandTitle: 'MedLabs Infrastructure',
    brandSub: 'ذكاء البنية التحتية · الأردن',
    nav: {
      dashboard: 'لوحة القيادة التنفيذية',
      servers: 'خوادم Windows',
      oracle: 'قاعدة بيانات Oracle',
      iis: 'خوادم الويب IIS والتطبيقات',
      network: 'الشبكات والربط',
      backups: 'النسخ الاحتياطي',
      alerts: 'التنبيهات والحوادث',
      analytics: 'التحليلات والذكاء الإحصائي',
      users: 'المستخدمون وسجل التدقيق',
      architecture: 'المجمّعات وكود .NET / Oracle',
    },
    header: {
      orgCrumb: 'مجموعة مختبرات ميدلابز الاستشارية · الأردن',
      signIn: 'تسجيل الدخول',
      claimAdmin: 'تعيين كلمة مرور المدير',
      signOut: 'تسجيل الخروج',
      roleLabel: 'الصلاحية',
      readOnlyBanner: 'جلسة معاينة للقراءة فقط — سجّل الدخول كمهندس أو مدير لتعديل الحوادث أو العتبات أو المستخدمين.',
    },
    status: {
      Online: 'متصل',
      Warning: 'تحذير',
      Critical: 'حرج',
      Offline: 'غير متصل',
    },
    severity: {
      Critical: 'حرج',
      High: 'مرتفع',
      Medium: 'متوسط',
      Low: 'منخفض',
      Information: 'معلومة',
    },
    incidentStatus: {
      Open: 'مفتوح',
      Acknowledged: 'تم الاستلام',
      'In Progress': 'قيد المعالجة',
      Resolved: 'تم الحل',
    },
    common: {
      search: 'بحث...',
      all: 'الكل',
      lastCheck: 'آخر فحص',
      actions: 'إجراءات',
      refresh: 'تحديث المجمّعات',
      copy: 'نسخ الكود',
      copied: 'تم النسخ',
      save: 'حفظ',
      cancel: 'إلغاء',
      close: 'إغلاق',
      noResults: 'لا توجد سجلات مطابقة.',
    },
  },
};
